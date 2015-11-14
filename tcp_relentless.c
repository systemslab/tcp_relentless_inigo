/*
 * Relentless TCP
 * 
 * This TCP is designed to efficiently and stably control hard against a limit
 * imposed by the network.  It assumes the presence of some mechanism in the
 * network to control the traffic.  (E.g. Weighted Fair Queuing)
 * 
 * It is the same as stock Linux Reno with SACK and ratehalving, except during
 * recovery, the window is only reduced by the actual losses.  This normally
 * results in a new cwnd that is exactly equal to the data actually delivered
 * during the lossy round trip.
 * 
 * Most of the complexity of this code comes from suppressing other algorithms
 * that implicitly reduce cwnd.  For example, if the connection runs out of
 * receiver window, ratehaving implicitly reduces cwnd to the flight size.
 * This reduction is effectively defeated by setting ssthresh to the explicitly
 * calculated (cwnd - retransmissions), such that by one RTT after the end of
 * recovery, cwnd comes back up to its prior value, minus any losses.
 *
 * IT IS NOT FAIR TO OTHER TCP IMPLEMENTATIONS OR OTHER PROTOCOLS.  It is
 * UNSAFE except on isolated networks, or networks that explicitly enforce
 * fairness.  Read and understand the README file before attempting to use this
 * code.
 *
 * Matt Mathis <mathis@psc.edu>, April 2008.
 */

#include <linux/module.h>
#include <net/tcp.h>

#define RELENTLESS_MAX_MARK 1024U
#define RELENTLESS_MAX_URGENCY 2048U

static unsigned int markthresh __read_mostly = 174;
module_param(markthresh, uint, 0644);
MODULE_PARM_DESC(markthresh, "rtts >  rtt_min + rtt_min * markthresh / 1024"
		" are considered marks of congestion, defaults to 174 out of 1024");

static unsigned int slowstart_rtt_observations_needed __read_mostly = 10U;
module_param(slowstart_rtt_observations_needed, uint, 0644);
MODULE_PARM_DESC(slowstart_rtt_observations_needed, "minimum number of RTT observations needed"
		 " to exit slowstart, defaults to 10");

static unsigned int debug_port __read_mostly = 5001;
module_param(debug_port, int, 0644);
MODULE_PARM_DESC(debug_port, "Port to match for debugging (0=all)");

static unsigned int debug_src __read_mostly = 167772162; // 10.0.0.2
module_param(debug_src, int, 0644);
MODULE_PARM_DESC(debug_src, "Source IP address to match for debugging (0=all)");

static bool deadline_aware  __read_mostly = false;
module_param(deadline_aware, bool, 0644);
MODULE_PARM_DESC(deadline_aware, "enable deadline awareness, defaults false");

/* Relentless structure */
struct relentless {
	u32 save_cwnd;     /* saved cwnd from before disorder or recovery */
	u32 cwndnlosses;   /* ditto plus total losses todate */
	u32 rtts_observed;
	u32 rtt_min;
	u32 rtt_thresh;
	u32 rtt_cwnd;      /* cwnd scaled by 1024 */
	u32 maxw_at_rtt_min;
	s32 packets_left;
	ktime_t deadline;
	bool debug;
};

inline static void relentless_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct relentless *ca = inet_csk_ca(sk);
	const struct inet_sock *inet = inet_sk(sk);
	u32 saddr = be32_to_cpu(inet->inet_saddr);
	ca->save_cwnd = 0;
	ca->cwndnlosses = 0;

	ca->rtts_observed = 0;
	ca->rtt_min = USEC_PER_SEC;
	ca->rtt_cwnd = tp->snd_cwnd << 10U;

	ca->maxw_at_rtt_min = tp->snd_cwnd;
	ca->packets_left = 0;
	ca->deadline = ktime_set(0, 0);

        ca->debug = false;
	pr_info("relentless: saddr=%u\n", saddr);
        if (debug_port == 0 || ((ntohs(inet->inet_dport) == debug_port) && saddr == debug_src))
                ca->debug = true;

	pr_info("relentless: rtt_cwnd=%u\n", ca->rtt_cwnd);
}

void relentless_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct relentless *ca = inet_csk_ca(sk);

	/* defeat all policy based cwnd reductions */
	tp->snd_cwnd = max(tp->snd_cwnd, tcp_packets_in_flight(tp));

//	if (!tcp_is_cwnd_limited(sk))
//		return;
//
//	/* In "safe" area, increase. */
//	if (tcp_in_slow_start(tp)) {
//		acked = tcp_slow_start(tp, acked);
//		ca->rtt_cwnd = tp->snd_cwnd << 10U;
//		if (ca->debug)
//			pr_info_ratelimited("relentless slow start: rtt_cwnd=%u, cwnd=%u, ssthresh=%u\n",
//				ca->rtt_cwnd, tp->snd_cwnd, tp->snd_ssthresh);
//		if (!acked)
//			return;
//	}
//	/* In dangerous area, increase slowly. */
//	tcp_cong_avoid_ai(tp, tp->snd_cwnd, acked);
//	ca->rtt_cwnd = tp->snd_cwnd << 10U;
//
//	if (ca->debug)
//		pr_info_ratelimited("relentless cong avoid: rtt_cwnd=%u, cwnd=%u, ssthresh=%u\n",
//			ca->rtt_cwnd, tp->snd_cwnd, tp->snd_ssthresh);

	ca->save_cwnd = tp->snd_cwnd;
	ca->cwndnlosses = tp->snd_cwnd + tp->total_retrans;
}

/* Slow start threshold follows cwnd, to defeat slowstart and cwnd moderation, etc */
static u32 relentless_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return max(tp->snd_cwnd, 2U);	/* Done already */
}

static void relentless_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct relentless *ca = inet_csk_ca(sk);

	switch (event) {
	case CA_EVENT_COMPLETE_CWR:
		/* set ssthresh to saved cwnd minus net losses */
		tp->snd_ssthresh = ca->cwndnlosses - tp->total_retrans;
	
	default:
		break;
	}
}

s64 relentless_urgency(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct relentless *ca = inet_csk_ca(sk);
	s64 urgency = 0, time_to_complete = 0;
	s64 dl_us = ktime_to_us(ca->deadline);

	if (dl_us <= 0)
		return urgency;

	time_to_complete = (ca->rtt_thresh) *
			   (ca->packets_left - tp->packets_out) * 4 / (3 * tp->snd_cwnd);
	urgency = RELENTLESS_MAX_URGENCY * time_to_complete / dl_us;
	urgency = clamp(urgency, (s64) 0U, (s64) RELENTLESS_MAX_URGENCY);

	pr_info_ratelimited("urgency=%u\n", (u32) urgency);
	return urgency;
}

void relentless_check_deadline(struct sock *sk, u32 rtt)
{
	struct relentless *ca = inet_csk_ca(sk);
	//struct tcp_sock *tp = tcp_sk(sk);
	u64 p = 0;
	ktime_t now = ktime_get();

	/* only change deadline info after the previous deadline has passed */
	if (!ktime_equal(ca->deadline, ktime_set(0, 0)) && ktime_before(ca->deadline, now))
		return;

	switch (sk->sk_priority) {
		//u32 load, w_load, rtt_load, rtt_thresh, quantum, w_per_p;
		//u32 load, quantum, w_per_p;
		case TC_PRIO_BESTEFFORT:
/* let's get other cases working first
			if (ca->rtt_min < INIGO_SUSPECT_RTT) {
				pr_warn_ratelimited("rtt_min is suspect. not calculating besteffort\n");
				return;
			}
			// doesn't work so well ... way too high
			//rtt_thresh = ca->rtt_min + (markthresh * ca->rtt_min / INIGO_MAX_MARK);
			//rtt_load = INIGO_LOAD_SCALE * (rtt - rtt_thresh) / rtt_thresh;
			load = ca->maxw_at_rtt_min / tp->snd_cwnd;
			quantum = NSEC_PER_SEC / 2;
			p = max(1U, load * quantum);
			w_per_p = p / NSEC_PER_USEC / ca->rtt_min;
			ca->packets_left = w_per_p * ca->maxw_at_rtt_min;
			pr_info_ratelimited("load=%u, p=%llu, w_per_p=%u, packets_left=%u, peak bw(Mbps)=%u, share bw(Mbps)=%u\n",
					     load, p, w_per_p, ca->packets_left,
					     8*1500*ca->maxw_at_rtt_min / ca->rtt_min,
					     8*1500*ca->packets_left / (u32) (p / NSEC_PER_USEC));
			break;
 */
		case TC_PRIO_FILLER:
			/* deadline unaware filler */
			return;
		case TC_PRIO_BULK:
			/* approximately 15MB/2s */
			ca->packets_left = 10000;
			p = NSEC_PER_SEC * 2;
			break;
		case 3:
			/* approximately 75MB/2s */
			ca->packets_left = 50000;
			p = NSEC_PER_SEC * 2;
			break;
		case TC_PRIO_INTERACTIVE_BULK:
			/* approximately 15KB/0.1s */
			ca->packets_left = 10;
			p = NSEC_PER_SEC / 10;
			break;
		case 5:
			/* approximately 30KB/0.1s */
			ca->packets_left = 20;
			p = NSEC_PER_SEC / 10;
			break;
		case TC_PRIO_INTERACTIVE:
			/* approximately 3KB/0.1s */
			ca->packets_left = 2;
			p = NSEC_PER_SEC / 10;
			break;
		case TC_PRIO_CONTROL:
			/* approximately 3KB/0.05s */
			ca->packets_left = 2;
			p = NSEC_PER_SEC / 20;
			break;
		case 8:
			/* from Brandt RTTS03 paper fig 7*/
			// util = 25 / 100;
			p = NSEC_PER_SEC * 2 / 10;
			ca->packets_left = p * ca->maxw_at_rtt_min * 25 / (ca->rtt_min * 100);
			break;
		case 9:
			/* from Brandt RTTS03 paper fig 7*/
			// util = 30 / 100;
			p = NSEC_PER_SEC * 5 / 10;
			ca->packets_left = p * ca->maxw_at_rtt_min * 30 / (ca->rtt_min * 100);
			break;
		case 10:
			/* from Brandt RTTS03 paper fig 7*/
			// util = 35 / 100;
			p = NSEC_PER_SEC;
			ca->packets_left = p * ca->maxw_at_rtt_min * 35 / (ca->rtt_min * 100);
			break;
		case 11:
			/* from Brandt RTTS03 paper fig 8*/
			// util = 20 / 100;
			p = NSEC_PER_SEC * 2 / 10;
			ca->packets_left = p * ca->maxw_at_rtt_min * 20 / (ca->rtt_min * 100);
			break;
		case 12:
			/* from Brandt RTTS03 paper fig 8*/
			// util = 60 / 100;
			p = NSEC_PER_SEC;
			ca->packets_left = p * ca->maxw_at_rtt_min * 60 / (ca->rtt_min * 100);
			break;
		case 13:
			/* from Brandt RTTS03 paper fig 8*/
			// util = 40 / 100;
			p = NSEC_PER_SEC * 5 / 10;
			ca->packets_left = p * ca->maxw_at_rtt_min * 40 / (ca->rtt_min * 100);
			break;
		case 14:
			p = NSEC_PER_SEC * 5 / 10;
			ca->packets_left = p * ca->maxw_at_rtt_min * 70 / (ca->rtt_min * 100);
			break;
		case TC_PRIO_MAX:
			p = NSEC_PER_SEC * 5 / 10;
			ca->packets_left = p * ca->maxw_at_rtt_min * 90 / (ca->rtt_min * 100);
			break;
	}

	ca->deadline = ktime_add_us(now, p);
}

static void relentless_pkts_acked(struct sock *sk, u32 num_acked, s32 rtt)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct relentless *ca = inet_csk_ca(sk);
	u32 r;

	if (rtt <= 0)
		return;

	ca->rtts_observed++;
	r = (u32) rtt;

	if (rtt < ca->rtt_min) {
		ca->rtt_min = r;
		ca->rtt_thresh = r + (r * markthresh / RELENTLESS_MAX_MARK);
	}

	if (ca->rtts_observed < slowstart_rtt_observations_needed)
		return;

	/* Mimic DCTCP ECN marking threshhold of approximately 0.17*BDP */
	if (r > ca->rtt_thresh) {
		bool backoff = tp->snd_cwnd >= tp->snd_ssthresh && prandom_u32_max(RELENTLESS_MAX_URGENCY) > relentless_urgency(sk);

		pr_info_ratelimited("relentless: backoff=%u\n", backoff);

		if (backoff) {
			ca->rtt_cwnd -= (num_acked << 6U);
			ca->rtt_cwnd = max(ca->rtt_cwnd, (2U << 10U));
		}

		if (ca->debug)
			pr_info_ratelimited("relentless backoff: rtt_min=%u, rtt_thresh=%u, rtt=%u, rtt_cwnd=%u, cwnd=%u, ssthresh=%u\n",
				ca->rtt_min, ca->rtt_thresh, (u32)r, ca->rtt_cwnd, tp->snd_cwnd, tp->snd_ssthresh);

		tp->snd_cwnd = (ca->rtt_cwnd >> 10U);

		if (tp->snd_cwnd <= tp->snd_ssthresh) {
			tp->snd_ssthresh = tp->snd_cwnd;

			if (ca->debug)
				pr_info_ratelimited("relentless exit slow start: rtt_min=%u, rtt_thresh=%u, rtt=%u, rtt_cwnd=%u, cwnd=%u, ssthresh=%u\n",
					ca->rtt_min, ca->rtt_thresh, (u32)r, ca->rtt_cwnd, tp->snd_cwnd, tp->snd_ssthresh);
		}
	} else {
		ca->maxw_at_rtt_min = max(ca->maxw_at_rtt_min, tp->snd_cwnd);
		ca->rtt_cwnd += (1 << 10U);
		tp->snd_cwnd = (ca->rtt_cwnd >> 10U);
	}

	if (deadline_aware && (tp->snd_cwnd > tp->snd_ssthresh)) {
		relentless_check_deadline(sk, (u32) rtt);
		ca->packets_left -= num_acked;
	}
}

static struct tcp_congestion_ops tcp_relentless = {
	.init		= relentless_init,
	.ssthresh	= relentless_ssthresh,
	.cong_avoid	= relentless_cong_avoid,
	.cwnd_event	= relentless_event,
	.pkts_acked 	= relentless_pkts_acked,
	.owner		= THIS_MODULE,
	.name		= "relentless",
};

static int __init relentless_register(void)
{
	return tcp_register_congestion_control(&tcp_relentless);
}

static void __exit relentless_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_relentless);
}

module_init(relentless_register);
module_exit(relentless_unregister);

MODULE_AUTHOR("Matt Mathis");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Relentless TCP");
