use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct Config {
    target_mac: String,
    router_ip: String,
    scan_interval: u64,
    smtp_host: String,
    smtp_pass: String,
    offline_threshold: u64,
    smtp_user: String,
    smtp_port: u16,
    recipients: Vec<String>,
}

fn main() {
    dotenvy::dotenv().ok();
    let config = envy::from_env::<Config>().expect("请检查 .env 文件配置是否完整");

    match envy::from_env::<Config>() {
        Ok(config) => {
            println!("配置加载成功！");
            println!("正在监控设备: {}", config.target_mac);
            println!("通知名单: {:?}", config.recipients);

        }
        Err(error) => {
            eprintln!("配置映射失败: {:#?}", error);
        }
    }


}
