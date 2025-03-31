use blake3;
use bulletproofs::{BulletproofGens, PedersenGens};
use chrono::Local;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use digest::{Digest, FixedOutput, FixedOutputReset, HashMarker, OutputSizeUser, Reset, Update};
use ff::Field;
use generic_array::GenericArray;
use merlin::Transcript;
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use rsntp::SntpClient;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::time::sleep;
use typenum::U64;

// --------------------------- Blake3 适配器 ---------------------------
pub mod blake3adapter {
    use super::*;
    use blake3::Hasher;
    use digest::{FixedOutput, FixedOutputReset, HashMarker, OutputSizeUser, Reset, Update};
    #[derive(Clone)]
    pub struct Blake3Adapter {
        pub hasher: Hasher,
    }
    impl Blake3Adapter {
        pub fn new() -> Self {
            Self {
                hasher: Hasher::new(),
            }
        }
    }
    impl Default for Blake3Adapter {
        fn default() -> Self {
            Self::new()
        }
    }
    impl OutputSizeUser for Blake3Adapter {
        type OutputSize = U64;
    }
    impl Update for Blake3Adapter {
        fn update(&mut self, data: &[u8]) {
            self.hasher.update(data);
        }
    }
    impl FixedOutput for Blake3Adapter {
        fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
            let result = self.finalize_fixed();
            out.copy_from_slice(result.as_slice());
        }
        fn finalize_fixed(self) -> GenericArray<u8, Self::OutputSize> {
            let mut buf = [0u8; 64];
            let mut reader = self.hasher.finalize_xof();
            reader.fill(&mut buf);
            GenericArray::clone_from_slice(&buf)
        }
    }
    impl FixedOutputReset for Blake3Adapter {
        fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
            let old_hasher = std::mem::replace(&mut self.hasher, Hasher::new());
            let mut reader = old_hasher.finalize_xof();
            let mut buf = [0u8; 64];
            reader.fill(&mut buf);
            out.copy_from_slice(&buf);
        }
    }
    impl Reset for Blake3Adapter {
        fn reset(&mut self) {
            *self = Self::new();
        }
    }
    impl HashMarker for Blake3Adapter {}
}

use blake3adapter::Blake3Adapter;

pub fn time_sync() -> u64 {
    let ntp_servers = vec![
        "ntp.aliyun.com",
        "ntp.tencent.com",
        "time.google.com",
        "pool.ntp.org",
        "time.cloudflare.com",
        "time.apple.com",
        "time.windows.com",
        "ntp.ntsc.ac.cn",
        "sgp.ntp.org.cn",
        "cn.pool.ntp.org",
        "north-america.pool.ntp.org",
        "africa.pool.ntp.org",
        "europe.pool.ntp.org",
    ];

    let client = SntpClient::new();
    for server in ntp_servers {
        if let Ok(result) = client.synchronize(server) {
            // 将同步到的时间转换为 chrono 的 DateTime
            if let Ok(ntp_datetime) = result.datetime().into_chrono_datetime() {
                return ntp_datetime.timestamp() as u64;
            }
        }
    }
    Local::now().timestamp() as u64
}

// --------------------------- 类型定义 ---------------------------
pub type PublicKey = RistrettoPoint;
pub type SecretKey = Scalar;
// 预签名定义为 (ẑ, c_vector, I)
pub type Signature = (Scalar, Vec<Scalar>, RistrettoPoint);
// 正式（适配器）签名定义为 (z, c_vector, I, J)
pub type AdaptorSig = (Scalar, Vec<Scalar>, RistrettoPoint, RistrettoPoint);
// 对于承诺，我们采用 Pedersen 承诺，其承诺值为 RistrettoPoint，证明为 Schnorr 协议证明 (R, s)
pub type Commitment = RistrettoPoint;
pub type Proof = (RistrettoPoint, Scalar);
// 时间锁承诺类型：增加时间戳字段
pub type TimeLockedCommitment = (Commitment, Proof, u64);

// --------------------------- 系统参数 Setup ---------------------------
#[derive(Clone)]
pub struct SystemParams {
    pub h: RistrettoPoint,
    pub bullet_gens: BulletproofGens,
    pub pedersen_gens: PedersenGens,
}

impl SystemParams {
    pub fn new() -> Self {
        // h 由固定字符串生成
        let h = RistrettoPoint::hash_from_bytes::<Blake3Adapter>(b"System Parameter H");
        // Bulletproofs 生成元（根据实际需求调整参数）
        let bullet_gens = BulletproofGens::new(256, 1);
        // Pedersen 生成元，默认两个生成元：B 与 B_blinding
        let pedersen_gens = PedersenGens::default();
        Self {
            h,
            bullet_gens,
            pedersen_gens,
        }
    }
}

// --------------------------- 哈希辅助函数 ---------------------------

/// 使用 Blake3Adapter 对传入数据进行哈希，返回 Scalar（作为挑战值）
/// 此处采用压缩后的公钥与 R 与 I 作为输入
fn hash_commitment(
    pk_set: &[PublicKey],
    R: &RistrettoPoint,
    I: &RistrettoPoint,
    msg: &[u8],
) -> Scalar {
    let mut hasher = Blake3Adapter::new();

    // 将 R 与 I 压缩值缓存
    let binding = R.compress();
    let compressed_r = binding.as_bytes();
    let binding = I.compress();
    let compressed_i = binding.as_bytes();

    // 使用缓存的 R 与 I 值进行更新
    for pk in pk_set {
        digest::Digest::update(&mut hasher, pk.compress().as_bytes());
    }
    digest::Digest::update(&mut hasher, compressed_r);
    digest::Digest::update(&mut hasher, compressed_i);
    digest::Digest::update(&mut hasher, msg);
    Scalar::from_hash(hasher)
}

// --------------------------- 密钥生成 KeyGen ---------------------------
pub fn key_gen(params: &SystemParams) -> Result<(PublicKey, SecretKey), &'static str> {
    let mut rng = OsRng;
    let sk = SecretKey::random(&mut rng);

    // 添加零值检查
    if sk.is_zero().into() {
        return Err("Generated secret key is zero, invalid");
    }

    let pk = params.h * sk;
    Ok((pk, sk))
}

// --------------------------- 预签名生成 PreSign ---------------------------
/// 此处采用标准 Schnorr 签名思路：
/// 1. 随机 r，令 R = h * r
/// 2. 计算 I = h * sk
/// 3. 计算挑战 c = H(pk_set, R, I, msg)
/// 4. 计算 ẑ = r + c * sk，令所有 c_i 均为 c
pub fn pre_sign(
    params: &SystemParams,
    pk_set: &[PublicKey],
    sk: &SecretKey,
    _Y: &PublicKey, // 保留参数兼容适配器部分
    msg: &[u8],
) -> Signature {
    let mut rng = OsRng;
    let r = SecretKey::random(&mut rng);
    let I = params.h * sk;
    let R = params.h * r;
    let c = hash_commitment(pk_set, &R, &I, msg);
    let z_hat = r + c * sk;
    let c_vec = vec![c; pk_set.len()];
    (z_hat, c_vec, I)
}

// --------------------------- 预签名验证 PreVerify ---------------------------
pub fn pre_verify(
    params: &SystemParams,
    pk_set: &[PublicKey],
    pre_sig: &Signature,
    _Y: &PublicKey,
    msg: &[u8],
) -> bool {
    let (z_hat, c_vec, I) = pre_sig;
    if c_vec.is_empty() {
        return false;
    }
    let c = c_vec[0];
    let R_prime = params.h * (*z_hat) - I * c;
    let c_calc = hash_commitment(pk_set, &R_prime, I, msg);
    c_vec.iter().all(|ci| *ci == c_calc)
}

// --------------------------- 适配器签名 Adapt ---------------------------
pub fn adaptor_sign(
    pre_sig: &Signature,
    _Y: &PublicKey,
    y: &SecretKey,
    pk_set: &[PublicKey],
    params: &SystemParams,
) -> AdaptorSig {
    let (z_hat, c_vec, I) = pre_sig;
    let J = params.h * y;
    // 检查 y 是否为零，如果是则 panic 或返回错误
    if y.is_zero().into() {
        panic!("Secret y is zero, inversion is undefined!");
    }
    let y_inv = y.invert();
    let z = z_hat * y_inv;
    (z, c_vec.clone(), *I, J)
}

// --------------------------- 正式签名验证 AS.Verify ---------------------------
pub fn as_verify(
    params: &SystemParams,
    pk_set: &[PublicKey],
    sigma: &AdaptorSig,
    _Y: &PublicKey,
    msg: &[u8],
    y: &SecretKey,
) -> bool {
    let (z, c_vec, I, _j) = sigma;
    let z_hat = z * y; // 恢复预签名部分
    if c_vec.is_empty() {
        return false;
    }
    let c = c_vec[0];
    let R_double = params.h * z_hat - I * c;
    let c_calc = hash_commitment(pk_set, &R_double, &I, msg);
    c_vec.iter().all(|ci| *ci == c_calc)
}

// --------------------------- 见证提取 Ext ---------------------------
pub fn extract(
    pre_sig: &Signature,
    sigma: &AdaptorSig,
    _Y: &PublicKey,
    _params: &SystemParams,
) -> Option<SecretKey> {
    let (z_hat, _, _) = pre_sig;
    let (z, _, _, _J) = sigma;
    if z.is_zero().into() {
        return None;
    }
    Some(*z_hat * z.invert())
}

// --------------------------- 时间锁承诺 Commit ---------------------------
pub fn commit(
    params: &SystemParams,
    _pk: &PublicKey,
    _pre_sig: &Signature,
    sig: &AdaptorSig,
    _Y: &PublicKey,
    _T: u64,
    _message: &[u8],
) -> TimeLockedCommitment {
    let mut rng = OsRng;
    // 记录当前时间戳（秒）
    let timestamp = time_sync();
    let r = SecretKey::random(&mut rng);
    let C = params.pedersen_gens.commit(sig.0, r);
    let blinding_base = params.pedersen_gens.B_blinding;
    let k = SecretKey::random(&mut rng);
    let R = blinding_base * k;

    let mut transcript = Transcript::new(b"PedersenCommitment");
    transcript.append_message(b"C", C.compress().as_bytes());
    transcript.append_message(b"R", R.compress().as_bytes());

    // 将时间戳作为承诺的一部分写入 transcript
    transcript.append_message(b"Timestamp", &timestamp.to_be_bytes());
    let mut challenge_bytes = [0u8; 64];
    transcript.challenge_bytes(b"e", &mut challenge_bytes);
    let e = Scalar::from_bytes_mod_order_wide(&challenge_bytes);
    let s = k + e * r;
    (C, (R, s), timestamp)
}

// --------------------------- 承诺验证 Verify ---------------------------
pub fn verify_commitment_with_timestamp(
    params: &SystemParams,
    _pk: &PublicKey,
    C: &Commitment,
    proof: &Proof,
    sig: &AdaptorSig,
    _Y: &PublicKey,
    _message: &[u8],
    timestamp: u64,
) -> bool {
    let (R, s) = proof;
    let blinding_base = params.pedersen_gens.B_blinding;
    let G = params.pedersen_gens.B;

    let mut transcript = Transcript::new(b"PedersenCommitment");
    transcript.append_message(b"C", C.compress().as_bytes());
    transcript.append_message(b"R", R.compress().as_bytes());
    transcript.append_message(b"Timestamp", &timestamp.to_be_bytes());

    let mut challenge_bytes = [0u8; 64];
    transcript.challenge_bytes(b"e", &mut challenge_bytes);
    let e = Scalar::from_bytes_mod_order_wide(&challenge_bytes);
    let lhs = blinding_base * s;
    let rhs = R + (C - G * sig.0) * e;
    lhs.ct_eq(&rhs).unwrap_u8() == 1
}

// ---------------------- 计算性时间锁 (基于哈希链) ----------------------
pub fn compute_time_lock(seed: &[u8], iterations: u64) -> Vec<u8> {
    let mut output = seed.to_vec();
    for _ in 0..iterations {
        let mut hasher = Blake3Adapter::new();
        digest::Digest::update(&mut hasher, &output);
        output = hasher.finalize_fixed().to_vec();
    }
    output
}

// ---------------------- 时间前打开承诺算法 Open ----------------------
pub fn open_commit(
    _params: &SystemParams,
    _pre_sig: &Signature,
    sigma: &AdaptorSig,
    _Y: &PublicKey,
    _T: u64,
) -> AdaptorSig {
    sigma.clone()
}

// ---------------------- 时间后打开承诺算法 F.Open ----------------------
pub fn f_open(
    _params: &SystemParams,
    _msg: &[u8],
    _pk: &PublicKey,
    _pre_sig: &Signature,
    _Y: &PublicKey,
    commit: &TimeLockedCommitment,
    sigma: &AdaptorSig,
    T: u64,
) -> Result<AdaptorSig, &'static str> {
    let (_commit_value, _proof, commit_timestamp) = commit;
    let now = time_sync();

    if now < commit_timestamp + T {
        Err("Time lock has not expired yet")
    } else {
        Ok(sigma.clone())
    }
}

// ---------------------- 延迟后执行 ----------------------
pub async fn execute_with_delay<T>(
    delay_seconds: u64,
    params: &SystemParams,
    msg: &[u8],
    pk_set: &[PublicKey],
    pre_sig: &Signature,
    Y: &PublicKey,
    time_locked_commitment: &TimeLockedCommitment,
    adaptor: &AdaptorSig,
    f_open_func: T,
) -> Result<(), &'static str>
where
    T: FnOnce(
        &SystemParams,
        &[u8],
        &PublicKey,
        &Signature,
        &PublicKey,
        &TimeLockedCommitment,
        &AdaptorSig,
        u64,
    ) -> Result<AdaptorSig, &'static str>,
{
    // 模拟异步时间延迟
    sleep(Duration::from_secs(delay_seconds)).await;

    // 执行 F.Open
    match f_open_func(
        params,
        msg,
        &pk_set[0],
        pre_sig,
        Y,
        time_locked_commitment,
        adaptor,
        delay_seconds,
    ) {
        Ok(sigma_f_open) => {
            println!("F.Open 成功，得到的签名: {:?}", sigma_f_open);
            Ok(())
        }
        Err(e) => {
            println!("F.Open 失败: {}", e);
            Err(e)
        }
    }
}

// --------------------------- 签名链接 Link ---------------------------
pub fn link(sigma1: &AdaptorSig, sigma2: &AdaptorSig) -> bool {
    sigma1 == sigma2
}
