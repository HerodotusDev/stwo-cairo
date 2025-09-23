use std::time::{Duration, Instant};

use cairo_air::verifier::verify_cairo;
use cairo_air::PreProcessedTraceVariant;
use dev_utils::utils::{
    get_compiled_cairo_program_path, run_program_and_adapter_shards, ProgramType,
};
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;
use stwo_cairo_prover::prover::prove_cairo;
use tracing::{info, span, Level};
use tracing_subscriber::fmt::format::FmtSpan;

fn main() {
    // Enable tracing logs for timing visibility.
    tracing_subscriber::fmt()
        .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
        .init();

    let _span = span!(Level::INFO, "fib4m_shards_bench").entered();

    // Match test_prove_verify_fibonacci_4m_shards setup.
    const N_STEPS: usize = 400_013;
    let compiled_program = get_compiled_cairo_program_path("test_prove_verify_fibonacci_100k");

    info!(
        "Loading shards from compiled program: {:?}",
        compiled_program
    );
    let t0 = Instant::now();
    let shards =
        run_program_and_adapter_shards(&compiled_program, ProgramType::Json, None, N_STEPS / 2);
    let load_dur = t0.elapsed();
    info!("Loaded {} shards in {:.3?}", shards.len(), load_dur);

    let preprocessed_trace = PreProcessedTraceVariant::CanonicalWithoutPedersen;

    // Prove+verify each shard sequentially (streaming-style).
    let t_all = Instant::now();
    let mut prove_durs: Vec<Duration> = Vec::new();
    let mut verify_durs: Vec<Duration> = Vec::new();
    let mut combined_durs: Vec<Duration> = Vec::new();
    for (i, shard) in shards.into_iter().enumerate() {
        info!(
            "Proving shard {} (initial_pc={}, final_pc={})",
            i + 1,
            shard.state_transitions.initial_state.pc.0,
            shard.state_transitions.final_state.pc.0
        );
        let t_prove = Instant::now();
        let proof =
            prove_cairo::<Blake2sMerkleChannel>(shard, PcsConfig::default(), preprocessed_trace)
                .expect("prove_cairo failed");
        let prove_dur = t_prove.elapsed();
        info!("Proved shard {} in {:.3?}", i + 1, prove_dur);

        let t_verify = Instant::now();
        verify_cairo::<Blake2sMerkleChannel>(proof, preprocessed_trace)
            .expect("verify_cairo failed");
        let verify_dur = t_verify.elapsed();
        info!("Verified shard {} in {:.3?}", i + 1, verify_dur);

        prove_durs.push(prove_dur);
        verify_durs.push(verify_dur);
        combined_durs.push(prove_dur + verify_dur);
    }
    let total_dur = t_all.elapsed();

    // Summarize.
    let n = combined_durs.len();

    // Combined stats (prove + verify)
    let mut durs = combined_durs.clone();
    durs.sort();
    let sum_combined = durs.iter().fold(Duration::ZERO, |acc, d| acc + *d);
    let avg_combined = sum_combined / (n as u32);
    let p50_combined = durs[n / 2];
    let p95_combined = durs[((n as f32 * 0.95).floor() as usize).min(n - 1)];
    let max_combined = *durs.last().unwrap();

    // Separate totals and avgs
    let total_prove: Duration = prove_durs.iter().copied().sum();
    let total_verify: Duration = verify_durs.iter().copied().sum();
    let avg_prove = total_prove / (n as u32);
    let avg_verify = total_verify / (n as u32);

    println!(
        "Shards: {} | load: {:.3?} | total: {:.3?} | prove_total: {:.3?} | verify_total: {:.3?} | avg_prove: {:.3?} | avg_verify: {:.3?} | combined avg: {:.3?} | p50: {:.3?} | p95: {:.3?} | max: {:.3?}",
        n,
        load_dur,
        total_dur,
        total_prove,
        total_verify,
        avg_prove,
        avg_verify,
        avg_combined,
        p50_combined,
        p95_combined,
        max_combined
    );
}
