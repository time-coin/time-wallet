use wallet::{NetworkType, Wallet};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TIME Coin Wallet with QR Code ===\n");
    let wallet = Wallet::new(NetworkType::Mainnet)?;
    println!("📍 Your Wallet Address:");
    println!("   {}\n", wallet.address_string());
    println!("📱 QR Code (scan with mobile wallet):");
    println!("{}", wallet.address_qr_code()?);
    println!("\n✅ Wallet created successfully!");
    println!("   Network: {:?}", wallet.network());
    println!("   Public Key: {}", wallet.public_key_hex());
    Ok(())
}
