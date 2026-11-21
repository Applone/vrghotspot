pub fn default_user_agent() -> String {
    const MIHOMO_VERSION: &str = env!("VRG_MIHOMO_VERSION_BUILT");
    format!(
        "{}/{} ClashMeta/{} (like Mihomo/{})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        MIHOMO_VERSION,
        MIHOMO_VERSION,
    )
}
