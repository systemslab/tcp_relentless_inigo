/*
 * Relentless DCTCP
 * 
 * This TCP is descended from DCTCP and Relentless. Rather than backing off
 * according to a congestion ratio once per RTT, it backs off by a fixed
 * fraction of the bytes corresponding to each ACK. In addition to using ECN
 * markings, it falls back to a similar RTT threshold.
 *
 * The idea for this style of per-ACK response came from Bob Briscoe.
 *
 * Unlike the original Relentless TCP, this variant is safe to deploy on
 * networks even if the network is not actively managing congestion.
 *
 * Andrew Shewmaker <shewa@lanl.gov>, November 2015.
 */

#include <linux/module.h>
#include <net/tcp.h>

#define RELENTLESS_MAX_MARK 1024U
#define RELENTLESS_WIN_SCALE 1024U

static unsigned int markthresh __read_mostly = 174;
module_param(markthresh, uint, 0644);
MODULE_PARM_DESC(markthresh, "rtts >  rtt_min + rtt_min * markthresh / 1024"
		" are considered marks of congestion, defaults to 174 out of 1024");

static unsigned int slowstart_rtt_observations_needed __read_mostly = 10U;
module_param(slowstart_rtt_observations_needed, uint, 0644);
MODULE_PARM_DESC(slowstart_rtt_observations_needed, "minimum number of RTT observations needed"
		 " to exit slowstart, defaults to 10");

static unsigned int detect __read_mostly = 1;
module_param(detect, int, 0644);
MODULE_PARM_DESC(detect, "Detect congestion (0=RTT, 1=ECN, 2=both), defaults to 2");

static unsigned int debug_port __read_mostly = 5001;
module_param(debug_port, int, 0644);
MODULE_PARM_DESC(debug_port, "Port to match for debugging (0=all)");

static unsigned int debug_src __read_mostly = 167772162; // 10.0.0.2
module_param(debug_src, int, 0644);
MODULE_PARM_DESC(debug_src, "Source IP address to match for debugging (0=all)");

/* Relentless structure */
struct relentless {
	u32 cwndnlosses;   /* saved cwnd plus total losses before disorder or recovery */
	u32 rtts_observed;
	u32 rtt_min;
	u32 rtt_thresh;
	u32 rtt_cwnd;      /* cwnd scaled by RELENTLESS_WIN_SCALE */
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 delayed_ack_reserved;
	u32 ecn_cwnd;      /* cwnd pkts scaled by RELENTLESS_WIN_SCALE */
	u8 ce_state;
	bool debug;
};

inline static void relentless_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct relentless *ca = inet_csk_ca(sk);
	const struct inet_sock *inet = inet_sk(sk);
	u32 saddr = be32_to_cpu(inet->inet_saddr);
	ca->cwndnlosses = 0;

	ca->rtts_observed = 0;
	ca->rtt_min = USEC_PER_SEC;
	ca->rtt_cwnd = ca->ecn_cwnd = tp->snd_cwnd << 10U;

        ca->debug = false;
	pr_info("relentless: saddr=%u\n", saddr);
/*
        if (debug_port == 0 || ((ntohs(inet->inet_dport) == debug_port) && saddr == debug_src))
                ca->debug = true;
 */

	pr_info("relentless init: rtt_cwnd=%u\n", ca->rtt_cwnd);

	if ((tp->ecn_flags & TCP_ECN_OK) ||
	    (sk->sk_state == TCP_LISTEN ||
	     sk->sk_state == TCP_CLOSE)) {

		ca->prior_snd_una = tp->snd_una;
		ca->prior_rcv_nxt = tp->rcv_nxt;

		ca->delayed_ack_reserved = 0;
		ca->ce_state = 0;
		return;
	}
}

void relentless_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct relentless *ca = inet_csk_ca(sk);
	u32 cwnd;

	/* defeat all policy based cwnd reductions */
	tp->snd_cwnd = max(tp->snd_cwnd, tcp_packets_in_flight(tp));

	if (!tcp_is_cwnd_limited(sk))
		return;

	switch (detect) {
	case 1:
		cwnd = (ca->ecn_cwnd >> 10U);
		break;
	case 2:
		cwnd = min(ca->rtt_cwnd, ca->ecn_cwnd) >> 10U;
		break;
	default:
		cwnd = (ca->rtt_cwnd >> 10U);
		break;
	}

	if (tcp_in_slow_start(tp))
		tp->snd_cwnd = min(cwnd, tp->snd_ssthresh);
	else
		tp->snd_cwnd = cwnd;

	ca->cwndnlosses = tp->snd_cwnd + tp->total_retrans;

	if (ca->debug)
		pr_info_ratelimited("relentless: cwnd=%u, ssthresh=%u\n",
			tp->snd_cwnd, tp->snd_ssthresh);
}

/* Slow start threshold follows cwnd, to defeat slowstart and cwnd moderation, etc */
static u32 relentless_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return max(tp->snd_cwnd, 2U);	/* Done already */
}

/* Minimal DCTP CE state machine:
 *
 * S:	0 <- last pkt was non-CE
 *	1 <- last pkt was CE
 */

static void dctcp_ce_state_0_to_1(struct sock *sk)
{
	struct relentless *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=0 to CE=1 and delayed
	 * ACK has not sent yet.
	 */
	if (!ca->ce_state && ca->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=0. */
		tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = ca->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 1;

	tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
}

static void dctcp_ce_state_1_to_0(struct sock *sk)
{
	struct relentless *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=1 to CE=0 and delayed
	 * ACK has not sent yet.
	 */
	if (ca->ce_state && ca->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=1. */
		tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = ca->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 0;

	tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
}

static void relentless_update_ack_reserved(struct sock *sk, enum tcp_ca_event ev)
{
	struct relentless *ca = inet_csk_ca(sk);

	switch (ev) {
	case CA_EVENT_DELAYED_ACK:
		if (!ca->delayed_ack_reserved)
			ca->delayed_ack_reserved = 1;
		break;
	case CA_EVENT_NON_DELAYED_ACK:
		if (ca->delayed_ack_reserved)
			ca->delayed_ack_reserved = 0;
		break;
	default:
		/* Don't care for the rest. */
		break;
	}
}

static void relentless_event(struct sock *sk, enum tcp_ca_event ev)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct relentless *ca = inet_csk_ca(sk);

	switch (ev) {
	case CA_EVENT_ECN_IS_CE:
		dctcp_ce_state_0_to_1(sk);
		break;
	case CA_EVENT_ECN_NO_CE:
		dctcp_ce_state_1_to_0(sk);
		break;
	case CA_EVENT_DELAYED_ACK:
	case CA_EVENT_NON_DELAYED_ACK:
		relentless_update_ack_reserved(sk, ev);
		break;
	case CA_EVENT_COMPLETE_CWR:
		/* set ssthresh to saved cwnd minus net losses */
		tp->snd_ssthresh = ca->cwndnlosses - tp->total_retrans;
	
	default:
		break;
	}
}

static void relentless_pkts_acked(struct sock *sk, u32 num_acked, s32 rtt)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct relentless *ca = inet_csk_ca(sk);
	u32 r;

	ca->rtts_observed++;
	r = (u32) rtt;

	if (rtt > 0 && r < ca->rtt_min) {
		ca->rtt_min = r;
		ca->rtt_thresh = r + (r * markthresh / RELENTLESS_MAX_MARK);
	}

	/* Mimic DCTCP ECN marking threshhold of approximately 0.17*BDP */
	if (r > ca->rtt_thresh) {
		if (ca->rtts_observed > slowstart_rtt_observations_needed) {
			//ca->rtt_cwnd += (RELENTLESS_WIN_SCALE / tp->snd_cwnd);
			ca->rtt_cwnd -= min(ca->rtt_cwnd, num_acked << 6U);
			ca->rtt_cwnd = max(ca->rtt_cwnd, (2U << 10U));

			if (tcp_in_slow_start(tp))
				tp->snd_ssthresh = tp->snd_cwnd;
/*
			if (ca->debug)
				pr_info_ratelimited("relentless backoff: rtt_min=%u, rtt_thresh=%u, rtt=%u, rtt_cwnd=%u\n",
					ca->rtt_min, ca->rtt_thresh, (u32)r, ca->rtt_cwnd);
 */
		}

	} else {
		ca->rtt_cwnd += RELENTLESS_WIN_SCALE;
	}
}

static void relentless_in_ack_event(struct sock *sk, u32 flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct relentless *ca = inet_csk_ca(sk);
	u32 acked_bytes, mss;

	/* If ack did not advance snd_una, count dupack as MSS size.
	 * If ack did update window, do not count it at all.
	 */
	mss = inet_csk(sk)->icsk_ack.rcv_mss;
	acked_bytes = tp->snd_una - ca->prior_snd_una;
	if (acked_bytes == 0 && !(flags & CA_ACK_WIN_UPDATE))
		acked_bytes = mss;
	if (acked_bytes)
		ca->prior_snd_una = tp->snd_una;

	if (!(flags & CA_ACK_ECE)) {
		ca->ecn_cwnd += RELENTLESS_WIN_SCALE;
		return;
	}

	if (tcp_in_slow_start(tp))
		tp->snd_ssthresh = tp->snd_cwnd;

	//ca->ecn_cwnd += (RELENTLESS_WIN_SCALE / tp->snd_cwnd);
	ca->ecn_cwnd -= min(ca->ecn_cwnd, ((acked_bytes / mss) << 9U));
	ca->ecn_cwnd = max(ca->ecn_cwnd, (2U << 10U));

	if (ca->debug)
		pr_info_ratelimited("relentless backoff: acked_bytes=%u, decrement pkts=%u, ecn_cwnd=%u\n",
			acked_bytes, (acked_bytes / mss), ca->ecn_cwnd);
}

static struct tcp_congestion_ops tcp_relentless = {
	.init		= relentless_init,
	.ssthresh	= relentless_ssthresh,
	.cong_avoid	= relentless_cong_avoid,
	.in_ack_event   = relentless_in_ack_event,
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

MODULE_AUTHOR("Andrew Shewmaker");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Relentless DCTCP");
