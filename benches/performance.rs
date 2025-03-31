use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use LiuProject1::{
    adaptor_sign, as_verify, commit, execute_with_delay, extract, f_open, key_gen, pre_sign,
    pre_verify, time_sync, verify_commitment_with_timestamp, AdaptorSig, Signature, SystemParams,
};

// 生成系统参数和密钥
fn setup_system() -> SystemParams {
    SystemParams::new()
}

fn setup_keypair(params: &SystemParams) -> (RistrettoPoint, Scalar) {
    let (pk, sk) = key_gen(params).expect("Key generation failed");
    (pk, sk)
}

fn setup_commitment_and_signature(
    params: &SystemParams,
    pk_set: &[RistrettoPoint],
    sk: &Scalar,
) -> (RistrettoPoint, Signature, AdaptorSig) {
    let msg = b"Test message for benchmarking";

    let pre_sig = pre_sign(params, pk_set, sk, &pk_set[0], msg);
    let adaptor_sig = adaptor_sign(&pre_sig, &pk_set[0], &sk, pk_set, params);

    let commitment = commit(
        params,
        &pk_set[0],
        &pre_sig,
        &adaptor_sig,
        &pk_set[0],
        time_sync(),
        msg,
    );
    (commitment.0, pre_sig, adaptor_sig)
}

// 测试 PreSign 和 PreVerify
fn benchmark_pre_sign_and_verify(c: &mut Criterion) {
    let params = setup_system();
    let (pk, sk) = setup_keypair(&params);
    let pk_set = vec![pk];
    let msg = b"Benchmark pre_sign and pre_verify";

    c.bench_function("pre_sign", |b| {
        b.iter(|| pre_sign(&params, &pk_set, &sk, &pk, black_box(msg)))
    });

    let pre_sig = pre_sign(&params, &pk_set, &sk, &pk, msg);
    c.bench_function("pre_verify", |b| {
        b.iter(|| pre_verify(&params, &pk_set, &pre_sig, &pk, black_box(msg)))
    });
}

// 测试 AdaptorSign 和 AS.Verify
fn benchmark_adaptor_sign_and_verify(c: &mut Criterion) {
    let params = setup_system();
    let (pk, sk) = setup_keypair(&params);
    let pk_set = vec![pk];
    let msg = b"Benchmark adaptor_sign and as_verify";

    let pre_sig = pre_sign(&params, &pk_set, &sk, &pk, msg);
    let adaptor_sig = adaptor_sign(&pre_sig, &pk, &sk, &pk_set, &params);

    c.bench_function("adaptor_sign", |b| {
        b.iter(|| adaptor_sign(&pre_sig, &pk, &sk, &pk_set, &params))
    });

    c.bench_function("as_verify", |b| {
        b.iter(|| as_verify(&params, &pk_set, &adaptor_sig, &pk, black_box(msg), &sk))
    });
}

// 测试 Commit 和 VerifyCommitmentWithTimestamp
fn benchmark_commit_and_verify(c: &mut Criterion) {
    let params = setup_system();
    let (pk, sk) = setup_keypair(&params);
    let pk_set = vec![pk];
    let msg = b"Benchmark commit and verify_commitment_with_timestamp";

    let (_commit_value, pre_sig, adaptor_sig) =
        setup_commitment_and_signature(&params, &pk_set, &sk);

    c.bench_function("commit", |b| {
        b.iter(|| {
            commit(
                &params,
                &pk,
                &pre_sig,
                &adaptor_sig,
                &pk,
                time_sync(),
                black_box(msg),
            )
        })
    });

    let (commitment, proof, timestamp) = (
        _commit_value,
        (RistrettoPoint::identity(), Scalar::ZERO),
        time_sync(),
    );
    c.bench_function("verify_commitment_with_timestamp", |b| {
        b.iter(|| {
            verify_commitment_with_timestamp(
                &params,
                &pk,
                &commitment,
                &proof,
                &adaptor_sig,
                &pk,
                black_box(msg),
                timestamp,
            )
        })
    });
}

// 测试 Extract
fn benchmark_extract(c: &mut Criterion) {
    let params = setup_system();
    let (pk, sk) = setup_keypair(&params);
    let pk_set = vec![pk];
    let msg = b"Benchmark extract";

    let pre_sig = pre_sign(&params, &pk_set, &sk, &pk, msg);
    let adaptor_sig = adaptor_sign(&pre_sig, &pk, &sk, &pk_set, &params);

    c.bench_function("extract", |b| {
        b.iter(|| extract(&pre_sig, &adaptor_sig, &pk, &params))
    });
}

// 测试时间延迟执行
fn benchmark_execute_with_delay(c: &mut Criterion) {
    let params = setup_system();
    let (pk, sk) = setup_keypair(&params);
    let pk_set = vec![pk];
    let msg = b"Benchmark execute_with_delay";

    let pre_sig = pre_sign(&params, &pk_set, &sk, &pk, msg);
    let adaptor_sig = adaptor_sign(&pre_sig, &pk, &sk, &pk_set, &params);
    let time_locked_commitment =
        commit(&params, &pk, &pre_sig, &adaptor_sig, &pk, time_sync(), msg);

    c.bench_function("execute_with_delay", |b| {
        b.iter(|| {
            execute_with_delay(
                5,
                &params,
                msg,
                &pk_set,
                &pre_sig,
                &pk,
                &time_locked_commitment,
                &adaptor_sig,
                f_open,
            )
        })
    });
}

// 创建所有基准测试项
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(100);
    targets =
        benchmark_pre_sign_and_verify,
        benchmark_adaptor_sign_and_verify,
        benchmark_commit_and_verify,
        benchmark_extract,
        benchmark_execute_with_delay
}

criterion_main!(benches);
