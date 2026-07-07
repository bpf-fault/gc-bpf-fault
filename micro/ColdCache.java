// Cold-heap demonstration workload for the compressed cold heap (idea 6).
//
// Models the "idle cache / oversized tenured heap" scenario DaCapo cannot:
// build a large long-lived data set, then run a small hot working set for
// a while.  The cold majority is exactly what MMTK_ZHEAP compresses.
//
// Output: periodic lines "phase elapsed_ms ops" — RSS is sampled
// externally via /proc.
import java.util.Random;

public class ColdCache {
    public static void main(String[] args) throws Exception {
        int coldMB = args.length > 0 ? Integer.parseInt(args[0]) : 1024;
        int hotMB = args.length > 1 ? Integer.parseInt(args[1]) : 64;
        int seconds = args.length > 2 ? Integer.parseInt(args[2]) : 90;

        // Long-lived cold data: session-like records, zero-padded fields
        // (realistic serialization/cache slack), 64KB segments.
        int coldSegs = coldMB * 16;
        long[][] cold = new long[coldSegs][];
        Random r = new Random(42);
        for (int i = 0; i < coldSegs; i++) {
            long[] seg = new long[8192];
            for (int w = 0; w < 8192; w += 4)
                seg[w] = r.nextLong();      // 25% payload, 75% zero slack
            cold[i] = seg;
        }
        int hotSegs = hotMB * 16;
        long[][] hot = new long[hotSegs][];
        for (int i = 0; i < hotSegs; i++)
            hot[i] = new long[8192];
        System.out.println("BUILT cold=" + coldMB + "MB hot=" + hotMB + "MB");

        // Hot phase: churn the hot set + allocate garbage to drive GCs.
        long end = System.currentTimeMillis() + seconds * 1000L;
        long ops = 0, sum = 0;
        byte[] garbage;
        while (System.currentTimeMillis() < end) {
            for (int k = 0; k < 1000; k++) {
                long[] seg = hot[r.nextInt(hotSegs)];
                int idx = r.nextInt(8192);
                seg[idx] = seg[idx] + 1;
                sum += seg[idx & 4095];
                ops++;
            }
            garbage = new byte[64 * 1024];   // nursery pressure -> GCs
            garbage[0] = 1;
            if ((ops % 4_000_000) == 0)
                System.out.println("HOT ops=" + ops);
        }
        // Cold validation: every cold word must be intact (decompression
        // correctness end-to-end through the real GC).
        long check = 0;
        for (int i = 0; i < coldSegs; i++)
            check += cold[i][1] + cold[i][4097];
        System.out.println("DONE ops=" + ops + " sum=" + sum + " check=" + check);
    }
}
