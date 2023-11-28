use std::net::{TcpStream, Shutdown};
use std::io::{Write,Read};
use rand::rngs::OsRng;
use rand::{Rng, RngCore, thread_rng};
use aes_gcm::{KeyInit, Aes256Gcm, Key, Nonce};
use aes_gcm::aead::Aead;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CipherSuite, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload
};

struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

//Convert a 4 byte vector to an unsigned int
fn bytes_to_u32(length_vector: Vec<u8>) -> u32 {
    let mut length: u32 = 0;
    for byte in length_vector {
        length = (length << 8) | byte as u32;
    }
    length
}

//Convert an unsigned int to a 4 byte vector
fn u32_to_bytes(length: u32) -> Vec<u8> {
    let mut length_vector : Vec<u8> = Vec::with_capacity(4);
    for i in (0..4).rev() {
        // Extract individual bytes using bitwise operations
        let byte = ((length >> (i * 8)) & 0xFF) as u8;
        length_vector.push(byte);
    }
    length_vector
}
//Read the next 4 bytes as length, then constructing a new vector of that length and read that many bytes from stream.
fn read_from_stream(mut stream: TcpStream) {

}

// Given a key and plaintext, produce an AEAD ciphertext along with a nonce
fn encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&key[..32]));

    let mut rng = OsRng;
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
    [nonce_bytes.to_vec(), ciphertext].concat()
}

// Decrypt using a key and a ciphertext (nonce included) to recover the original
// plaintext
fn decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from_slice(&key[..32]));
    cipher
        .decrypt(
            Nonce::from_slice(&ciphertext[..12]),
            ciphertext[12..].as_ref(),
        )
        .unwrap()
}

fn register(
    mut stream: TcpStream,
    username: String,
    password: String,
    secret_message: String,
) {
    println!("Password Bytes: {:?}", password.as_bytes());
    let mut client_rng = OsRng;
    let client_registration_start_result =
        ClientRegistration::<DefaultCipherSuite>::start(&mut client_rng, password.as_bytes())
            .unwrap();
    let registration_request_bytes = client_registration_start_result.message.serialize();
    println!("Registration Request Bytes: {:?}", registration_request_bytes);
    let mut bytes_vector : Vec<u8> = vec![0]; // Represents this is a register operation
    let mut length = registration_request_bytes.len();
    println!("{}", length);
    let mut length_vector : Vec<u8> = Vec::with_capacity(4);
    for i in (0..4).rev() {
        // Extract individual bytes using bitwise operations
        let byte = ((length >> (i * 8)) & 0xFF) as u8;
        length_vector.push(byte);
    }
    println!("{:?}", length_vector);
    bytes_vector.extend(&length_vector);
    bytes_vector.extend(&registration_request_bytes);
    let username_bytes = username.as_bytes();
    println!("Username Bytes: {:?}", username_bytes);
    let username_length = username_bytes.len();
    let mut length_vector2 : Vec<u8> = Vec::with_capacity(4);
    for i in (0..4).rev() {
        // Extract individual bytes using bitwise operations
        let byte = ((username_length >> (i * 8)) & 0xFF) as u8;
        length_vector2.push(byte);
    }
    bytes_vector.extend(&length_vector2);
    bytes_vector.extend(username_bytes);
    println!("{:?}", bytes_vector);
    stream.write_all(&bytes_vector);
    stream.flush();
    let mut length_buffer: [u8; 4] = [0,0,0,0];
    stream.read_exact(&mut length_buffer);
    let mut length: usize = 0;
    for byte in length_buffer {
        length = (length << 8) | byte as usize;
    }
    let mut registration_response_buffer = vec![0;length];
    stream.read_exact(&mut registration_response_buffer);
    let client_finish_registration_result = client_registration_start_result
    .state
    .finish(
        &mut client_rng,
        password.as_bytes(),
        RegistrationResponse::deserialize(&registration_response_buffer).unwrap(),
        ClientRegistrationFinishParameters::default(),
    )
    .unwrap();
    let message_bytes = client_finish_registration_result.message.serialize();
    let registration_result_length = message_bytes.len();
    let mut registration_result_length_vector : Vec<u8> = Vec::with_capacity(4);
    for i in (0..4).rev() {
        // Extract individual bytes using bitwise operations
        let byte = ((registration_result_length >> (i * 8)) & 0xFF) as u8;
        registration_result_length_vector.push(byte);
    }
    let ciphertext = encrypt(
        &client_finish_registration_result.export_key,
        secret_message.as_bytes(),
    );
    let ciphertext_length = ciphertext.len();
    let mut ciphertext_length_vector : Vec<u8> = Vec::with_capacity(4);
    for i in (0..4).rev() {
        // Extract individual bytes using bitwise operations
        let byte = ((ciphertext_length >> (i * 8)) & 0xFF) as u8;
        ciphertext_length_vector.push(byte);
    }
    ciphertext_length_vector.extend(&ciphertext);
    ciphertext_length_vector.extend(&registration_result_length_vector);
    ciphertext_length_vector.extend(&message_bytes);
    stream.write_all(&ciphertext_length_vector);
}

fn login(mut stream: TcpStream,
    username: String,
    password: String,) -> Result<String, String>{
        println!("Password Bytes: {:?}", password.as_bytes());
        let mut client_rng = OsRng;
        let client_login_start_result =
        ClientLogin::<DefaultCipherSuite>::start(&mut client_rng, password.as_bytes()).unwrap();
        let credential_request_bytes = client_login_start_result.message.serialize();

        println!("Login Request Bytes: {:?}", credential_request_bytes);
        let mut bytes_vector : Vec<u8> = vec![1]; // Represents this is a login operation
        let mut length = credential_request_bytes.len();
        println!("{}", length);
        let mut length_vector : Vec<u8> = Vec::with_capacity(4);
        for i in (0..4).rev() {
            // Extract individual bytes using bitwise operations
            let byte = ((length >> (i * 8)) & 0xFF) as u8;
            length_vector.push(byte);
        }
        println!("{:?}", length_vector);
        bytes_vector.extend(&length_vector);
        bytes_vector.extend(&credential_request_bytes);
        let username_bytes = username.as_bytes();
        println!("Username Bytes: {:?}", username_bytes);
        let username_length = username_bytes.len();
        let mut length_vector2 : Vec<u8> = Vec::with_capacity(4);
        for i in (0..4).rev() {
            // Extract individual bytes using bitwise operations
            let byte = ((username_length >> (i * 8)) & 0xFF) as u8;
            length_vector2.push(byte);
        }
        bytes_vector.extend(&length_vector2);
        bytes_vector.extend(username_bytes);
        println!("{:?}", bytes_vector);
        stream.write_all(&bytes_vector);
        stream.flush();

        //Read Login Response
        let mut length_buffer: [u8; 4] = [0,0,0,0];
        stream.read_exact(&mut length_buffer);
        let mut length: usize = 0;
        for byte in length_buffer {
            length = (length << 8) | byte as usize;
        }
        let mut credential_response_buffer = vec![0;length];
        stream.read_exact(&mut credential_response_buffer);
        println!("Crdential Response Buffer: {:?}", credential_response_buffer);
        let result = client_login_start_result.state.finish(
            password.as_bytes(),
            CredentialResponse::deserialize(&credential_response_buffer).unwrap(),
            ClientLoginFinishParameters::default(),
        );

        if result.is_err() {
            // Client-detected login failure
            println!("Incorrect Password!");
            return Err(String::from("Incorrect password, please try again."));
        }

        let client_login_finish_result = result.unwrap();
        let credential_finalization_bytes = client_login_finish_result.message.serialize();
        let credential_finalization_length = credential_finalization_bytes.len();
        let mut credential_finalization_length_vector : Vec<u8> = Vec::with_capacity(4);
        for i in (0..4).rev() {
            // Extract individual bytes using bitwise operations
            let byte = ((credential_finalization_length >> (i * 8)) & 0xFF) as u8;
            credential_finalization_length_vector.push(byte);
        }
        println!("Credential Finalization Bytes: {:?}", credential_finalization_bytes);
        println!("Credential Finalization Length: {}", credential_finalization_length);
        println!("Credential Finalization Length Byte: {:?}", credential_finalization_length_vector);
        credential_finalization_length_vector.extend(credential_finalization_bytes);
        stream.write_all(&credential_finalization_length_vector);
        stream.flush();
        stream.read_exact(&mut length_buffer);
        let mut length: usize = 0;
        for byte in length_buffer {
            length = (length << 8) | byte as usize;
        }
        println!("Encrypted Ciphertext Length Bytes: {:?}", length_buffer);
        println!("Encrypted Ciphertext Length: {}", length);
        let mut encrypted_ciphertext = vec![0;length];
        stream.read_exact(&mut encrypted_ciphertext);
        println!("Encrypted Ciphertext: {:?}", encrypted_ciphertext);
        let ciphertext = decrypt(&client_login_finish_result.session_key,
            &encrypted_ciphertext,);
        println!("Ciphertext: {:?}", ciphertext);
        let plaintext = decrypt(
            &client_login_finish_result.export_key,
            &ciphertext,
        );
        String::from_utf8(plaintext).map_err(|_| String::from("UTF8 error"))
    }

fn close_connection(mut stream: TcpStream) {
    stream.write_all(&vec![2]);
}

fn main() {
    let mut length = 64;
    println!("{:?}", u32_to_bytes(length));
    println!("{:?}", bytes_to_u32(u32_to_bytes(length)));
    if let Ok(mut stream) = TcpStream::connect("127.0.0.1:7878") {
        let mut register_stream = stream.try_clone().unwrap();
        let mut login_stream = stream.try_clone().unwrap();
        let mut shutdown_stream = stream.try_clone().unwrap();
        println!("Connected to the server!");
        register(register_stream, "leo".to_string(), "123456".to_string(), "hello world".to_string());
        println!("{}", login(login_stream, "leo".to_string(), "123456".to_string()).unwrap());
        close_connection(shutdown_stream);
        stream.shutdown(Shutdown::Both);
    } else {
        println!("Couldn't connect to server...");
    }
}