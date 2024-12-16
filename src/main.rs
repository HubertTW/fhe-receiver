#![allow(warnings)]
use std::fs;
use std::io::Cursor;
use std::ops::Deref;
use tfhe::{ClientKey, FheUint, FheUint16Id};
use tfhe::prelude::FheDecrypt;

fn main() -> Result<(), Box<dyn std::error::Error>>{
    ///println!("deserializing client key...");
    let mut byte_vec = fs::read("client_key.bin")?;
    let ck = deserialize_ck(&byte_vec.into_boxed_slice().deref())?;
    println!("deserializing string...");
    let file = fs::read("sanitized_payload.bin")?;
    let enc_str = deserialize_str(&file, 4)?;
    let mut v:Vec<u8> = vec![];
    for i in enc_str{
        v.push(i.decrypt(&ck));
    }
    let res = String::from_utf8(v.clone()).unwrap();
    println!("the received msg: {:?}", res);

    Ok(())
}


fn deserialize_ck(serialized_data: &[u8]) -> Result<ClientKey, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let ck: ClientKey = bincode::deserialize_from(&mut to_des_data)?;
    Ok(ck)
}

fn deserialize_str(
    serialized_data: &[u8],
    content_size: u8
) -> Result<Vec<FheUint<FheUint16Id>>, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let mut v: Vec<FheUint<FheUint16Id>> = vec![];
    for _ in 0..content_size{
        // length of received string
        v.push(bincode::deserialize_from(&mut to_des_data)?);
    }
    Ok(v)
}
