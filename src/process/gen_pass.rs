use rand::seq::SliceRandom;

const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const NUMBER: &[u8] = b"123456789";
const SYMBOL: &[u8] = b"!@#$%^&*_";

pub fn process_genpass(
    length: u8,
    uppercase: bool,
    lowercase: bool,
    number: bool,
    symbol: bool,
) -> anyhow::Result<String> {
    let mut charset = Vec::new();
    let mut rng = rand::thread_rng();
    let mut password = Vec::new();
    if uppercase {
        charset.extend_from_slice(UPPER);
        password.push(*charset.choose(&mut rng).expect("UPPER won't be empty"));
    }
    if lowercase {
        charset.extend_from_slice(LOWER);
        password.push(*charset.choose(&mut rng).expect("LOWER won't be empty"));
    }
    if number {
        charset.extend_from_slice(NUMBER);
        password.push(*charset.choose(&mut rng).expect("NUMBER won't be empty"));
    }
    if symbol {
        charset.extend_from_slice(SYMBOL);
        password.push(*charset.choose(&mut rng).expect("SYMBOL won't be empty"));
    }

    for _ in 0..(length - password.len() as u8) {
        let c = charset
            .choose(&mut rng)
            .expect("chars won't be empty in this context");
        password.push(*c);
    }

    password.shuffle(&mut rng);

    let password = String::from_utf8(password)?;
    Ok(password)
}
