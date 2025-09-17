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
    const N_STEPS: usize = 16_000_013;
    let compiled_program = get_compiled_cairo_program_path("test_prove_verify_fibonacci_4M");

    info!("Loading shards from compiled program: {:?}", compiled_program);
    let t0 = Instant::now();
    let shards = run_program_and_adapter_shards(&compiled_program, ProgramType::Json, None, N_STEPS / 4);
    let load_dur = t0.elapsed();
    info!("Loaded {} shards in {:.3?}", shards.len(), load_dur);

    let preprocessed_trace = PreProcessedTraceVariant::CanonicalWithoutPedersen;

    // Prove+verify each shard sequentially (streaming-style).
    let t_all = Instant::now();
    let mut results: Vec<(usize, Duration)> = Vec::new();
    for (i, shard) in shards.into_iter().enumerate() {
        let t = Instant::now();
        info!(
            "Proving shard {} (initial_pc={}, final_pc={})",
            i + 1,
            shard.state_transitions.initial_state.pc.0,
            shard.state_transitions.final_state.pc.0
        );
        let proof = prove_cairo::<Blake2sMerkleChannel>(
            shard,
            PcsConfig::default(),
            preprocessed_trace,
        )
        .expect("prove_cairo failed");
        verify_cairo::<Blake2sMerkleChannel>(proof, preprocessed_trace)
            .expect("verify_cairo failed");
        let dur = t.elapsed();
        info!("Verified shard {} in {:.3?}", i + 1, dur);
        results.push((i, dur));
    }
    let total_dur = t_all.elapsed();

    // Summarize.
    let n = results.len();
    let mut durs: Vec<Duration> = results.into_iter().map(|(_, d)| d).collect();
    durs.sort();
    let sum = durs.iter().fold(Duration::ZERO, |acc, d| acc + *d);
    let avg = sum / (n as u32);
    let p50 = durs[n / 2];
    let p95 = durs[((n as f32 * 0.95).floor() as usize).min(n - 1)];
    let max = *durs.last().unwrap();

    println!(
        "Shards: {} | load: {:.3?} | total: {:.3?} | avg: {:.3?} | p50: {:.3?} | p95: {:.3?} | max: {:.3?}",
        n, load_dur, total_dur, avg, p50, p95, max
    );
}
