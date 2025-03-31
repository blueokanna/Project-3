use curve25519_dalek::{RistrettoPoint, Scalar};
use log::{error, info, LevelFilter};
use rand::rngs::OsRng;
use LiuProject1::{
    adaptor_sign, as_verify, execute_with_delay, key_gen, link, pre_sign, AdaptorSig, PublicKey,
    SecretKey, Signature, SystemParams, TimeLockedCommitment,
};

// --------------------------- 主函数 ---------------------------
#[tokio::main]
async fn main() {
    // 初始化日志（生产环境请根据需要配置日志系统）
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .init();

    // 1) Setup
    info!("正在生成系统参数...");
    let params = SystemParams::new();
    info!("系统参数生成成功!");

    // 2) KeyGen
    info!("正在生成公私钥对...");
    let (pk, sk) = key_gen(&params).unwrap();
    info!("公私钥对生成成功!");
    info!("公钥: {:?}", pk);
    info!("私钥: {:?}", sk);

    // 3) 准备测试数据
    let pk_set = vec![pk]; // 单个公钥组成的用户组
    let msg1 = b"Test Message Hello'"; // 第一个待签名消息
    let msg2 = b"Test Message World'"; // 第二个待签名消息

    // 模拟困难关系对 (Y, y)；Y在预签名中未参与计算，但在适配器签名中用于绑定见证
    let Y = pk;
    let mut rng = OsRng;
    let y = SecretKey::random(&mut rng);

    // 4) 预签名生成 PreSign
    info!("正在生成预签名...");
    let pre_sig1 = pre_sign(&params, &pk_set, &sk, &Y, msg1);
    let pre_sig2 = pre_sign(&params, &pk_set, &sk, &Y, msg2);
    info!("预签名生成成功!\n预签名1: {:?}", pre_sig1);
    info!("预签名生成成功!\n预签名2: {:?}", pre_sig2);

    // 5) 适配器签名 Adapt
    info!("正在生成适配器签名...");
    let adaptor1 = adaptor_sign(&pre_sig1, &Y, &y, &pk_set, &params);
    let adaptor2 = adaptor_sign(&pre_sig2, &Y, &y, &pk_set, &params);
    info!("适配器签名生成成功!\n适配器签名1: {:?}", adaptor1);
    info!("适配器签名生成成功!\n适配器签名2: {:?}", adaptor2);

    // 6) 正式签名验证 AS.Verify
    info!("正在验证正式签名...");
    if as_verify(&params, &pk_set, &adaptor1, &Y, msg1, &y) {
        info!("正式签名1验证通过!");
    } else {
        error!("正式签名1验证失败!");
    }

    if as_verify(&params, &pk_set, &adaptor2, &Y, msg2, &y) {
        info!("正式签名2验证通过!");
    } else {
        error!("正式签名2验证失败!");
    }

    let delay_seconds = 5; // 设置延迟时间为5秒

    // 手动构造 TimeLockedCommitment
    let time_locked_commitment: TimeLockedCommitment = {
        let r = Scalar::random(&mut rng);
        let R = RistrettoPoint::random(&mut rng);
        (R, (R, r), 0) // 这里的 0 是时间戳字段
    };

    // F.Open 操作
    let f_open_func = |params: &SystemParams,
                       msg: &[u8],
                       pk: &PublicKey,
                       pre_sig: &Signature,
                       Y: &PublicKey,
                       time_locked_commitment: &TimeLockedCommitment,
                       adaptor: &AdaptorSig,
                       delay_seconds: u64| {
        info!("正在执行 F.Open 操作...");
        Ok(adaptor.clone()) // 这里只是示例，实际逻辑需要根据需求实现
    };

    // 调用带延迟的执行函数
    if let Err(e) = execute_with_delay(
        delay_seconds,
        &params,
        msg1,
        &pk_set,
        &pre_sig1,
        &Y,
        &time_locked_commitment,
        &adaptor1,
        f_open_func,
    )
    .await
    {
        error!("F.Open 操作失败: {}", e);
    }

    if let Err(e) = execute_with_delay(
        delay_seconds,
        &params,
        msg2,
        &pk_set,
        &pre_sig2,
        &Y,
        &time_locked_commitment,
        &adaptor2,
        f_open_func,
    )
    .await
    {
        error!("F.Open 操作失败: {}", e);
    }

    // 7) 签名链接 Link
    info!("正在执行签名链接检测...");
    let linked = link(&adaptor1, &adaptor2);
    if linked {
        info!("签名是链接的");
    } else {
        info!("签名未链接");
    }
}
