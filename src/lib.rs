//! # mysql_crypt
//!

use anyhow::{anyhow, bail, Result};
use crypto::aes;
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::symmetriccipher::Encryptor;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Encrypted(pub Vec<u8>);

impl Encrypted {
    pub fn to_base64(&self) -> String {
        base64::encode(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MysqlAes128 {
    key: Vec<u8>,
}

impl MysqlAes128 {
    pub fn new(password: &[u8]) -> MysqlAes128 {
        let mut key = vec![0; 16];
        for part in password.chunks(key.len()) {
            for (i, &b) in part.iter().enumerate() {
                key[i] ^= b;
            }
        }
        MysqlAes128 { key }
    }

    pub fn encrypt(&self, plain_text: &[u8]) -> Result<Encrypted> {
        if plain_text.is_empty() {
            return Ok(Encrypted(Vec::new()));
        }

        let mut buf = vec![0; (plain_text.len() / 16 + 1) * 16];
        let mut w_buf = RefWriteBuffer::new(&mut buf);
        {
            let mut encryptor =
                aes::ecb_encryptor(aes::KeySize::KeySize128, &self.key, PkcsPadding);
            let mut r_buf = RefReadBuffer::new(plain_text);
            if let BufferResult::BufferOverflow = encryptor
                .encrypt(&mut r_buf, &mut w_buf, true)
                .map_err(|err| anyhow!("{:?}", err))?
            {
                bail!("BufferOverflow");
            }
        }

        let mut r_buf = w_buf.take_read_buffer();
        let remain = r_buf.take_remaining();
        let mut encoded = Vec::with_capacity(remain.len());
        encoded.extend(remain.iter().to_owned());
        Ok(Encrypted(encoded))
    }

    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.is_empty() {
            return Ok(Vec::new());
        }

        let mut decryptor = aes::ecb_decryptor(aes::KeySize::KeySize128, &self.key, PkcsPadding);
        let mut r_buf = RefReadBuffer::new(encrypted);
        let mut buf = vec![0; encrypted.len()];
        let mut w_buf = RefWriteBuffer::new(&mut buf);
        if let BufferResult::BufferOverflow = decryptor
            .decrypt(&mut r_buf, &mut w_buf, true)
            .map_err(|err| anyhow!("{:?}", err))?
        {
            bail!("BufferOverflow");
        }

        let mut r_buf = w_buf.take_read_buffer();
        let remain = r_buf.take_remaining();
        let mut decoded = Vec::with_capacity(remain.len());
        decoded.extend(remain.iter().to_owned());
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    fn enc_dec_test_base(key: &[u8], plain: &[u8], expected: &str) {
        let c = crate::MysqlAes128::new(key);
        let encrypted = c.encrypt(plain).unwrap();
        assert_eq!(encrypted.to_base64().as_str(), expected);

        let decoded = c.decrypt(&encrypted.0).unwrap();
        assert_eq!(decoded, plain);
    }

    #[test]
    fn plain_aaa_35() {
        enc_dec_test_base(
            "abcdefg".as_bytes(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_bytes(),
            "GCMRNJ2MlKXq7K+73iTIIBgjETSdjJSl6uyvu94kyCAbTya4Mp7Jo01e6I0Jfo7I",
        );
    }

    #[test]
    fn plain_0() {
        enc_dec_test_base("abcdefg".as_bytes(), "".as_bytes(), "");
    }
}
