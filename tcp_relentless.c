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

/* Relentless structure */
struct relentless {
    u32	save_cwnd;  /* saved cwnd from before disorder or recovery */
    u32 cwndnlosses;  /* ditto plus total losses todate */
};

inline static void relentless_init(struct sock *sk)
{
	struct relentless *w = inet_csk_ca(sk);
	w->save_cwnd = 0;
	w->cwndnlosses = 0;
}

static void relentless_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct relentless *rl = inet_csk_ca(sk);

    /* defeat all policy based cwnd reductions */
    tp->snd_cwnd = max(tp->snd_cwnd, tcp_packets_in_flight(tp));

    tcp_reno_cong_avoid(sk, ack, acked);
    rl->save_cwnd = tp->snd_cwnd;
    rl->cwndnlosses = tp->snd_cwnd + tp->total_retrans;
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
    struct relentless *rl = inet_csk_ca(sk);

    switch (event) {

    case CA_EVENT_COMPLETE_CWR:
	/* set ssthresh to saved cwnd minus net losses */
	tp->snd_ssthresh = rl->cwndnlosses - tp->total_retrans;
	
    default:
	break;
    }
}

static struct tcp_congestion_ops tcp_relentless = {
	.name		= "relentless",
	.owner		= THIS_MODULE,
	.init		= relentless_init,
	.ssthresh	= relentless_ssthresh,
	.cong_avoid	= relentless_cong_avoid,
	.cwnd_event	= relentless_event
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
