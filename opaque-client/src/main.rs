use std::net::{TcpStream, Shutdown};
use std::io::{Write,Read};
use std::time::Instant;
use rand::rngs::OsRng;
use rand::{Rng, RngCore, thread_rng};
use threadpool::ThreadPool;
use aes_gcm::{KeyInit, Aes256Gcm, Key, Nonce};
use aes_gcm::aead::Aead;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CipherSuite, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerSetup
};

struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

//Convert a 4 byte vector to an unsigned int
fn bytes_to_u32(length_vector: &Vec<u8>) -> u32 {
    let mut length: u32 = 0;
    for byte in length_vector {
        length = (length << 8) | *byte as u32;
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
fn read_from_stream(mut stream: &TcpStream) -> Vec<u8> {
    let mut length_buffer: [u8; 4] = [0,0,0,0];
    stream.read_exact(&mut length_buffer).unwrap();
    let length = bytes_to_u32(&mut length_buffer.to_vec());
    let mut byte_vector: Vec<u8> = vec![0;length.try_into().unwrap()];
    stream.read_exact(&mut byte_vector).unwrap();
    byte_vector
}

//Write 4 bytes representing the length of byte_vector to the stream, then write byte_vector to the stream
fn write_to_stream(mut stream: &TcpStream, byte_vector: &Vec<u8>) {
    let length = byte_vector.len();
    let mut length_vector = u32_to_bytes(length.try_into().unwrap());
    length_vector.extend(byte_vector);
    stream.write_all(&length_vector).unwrap();
    stream.flush().unwrap();
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
    //println!("Password Bytes: {:?}", password.as_bytes());
    let mut client_rng = OsRng;
    let client_registration_start_result =
        ClientRegistration::<DefaultCipherSuite>::start(&mut client_rng, password.as_bytes())
            .unwrap();
    let registration_request_bytes = client_registration_start_result.message.serialize().to_vec();
    //println!("Registration Request Bytes: {:?}", registration_request_bytes);
    let bytes_vector : Vec<u8> = vec![0]; // Represents this is a register operation
    stream.write_all(&bytes_vector).unwrap();
    write_to_stream(&stream, &registration_request_bytes);
    let username_bytes = username.as_bytes().to_vec();
    //println!("Username Bytes: {:?}", username_bytes);

    //println!("{:?}", bytes_vector);
    write_to_stream(&stream, &username_bytes);
    let registration_response_buffer = read_from_stream(&stream);
    let client_finish_registration_result = client_registration_start_result
    .state
    .finish(
        &mut client_rng,
        password.as_bytes(),
        RegistrationResponse::deserialize(&registration_response_buffer).unwrap(),
        ClientRegistrationFinishParameters::default(),
    )
    .unwrap();
    let registration_result_bytes = client_finish_registration_result.message.serialize().to_vec();
    let ciphertext = encrypt(
        &client_finish_registration_result.export_key,
        secret_message.as_bytes(),
    );
    write_to_stream(&stream, &ciphertext);
    write_to_stream(&stream, &registration_result_bytes);
}

fn login(mut stream: TcpStream,
    username: String,
    password: String,) -> Result<Vec<u8>, String>{
        //println!("Password Bytes: {:?}", password.as_bytes());
        let mut client_rng = OsRng;
        let client_login_start_result =
        ClientLogin::<DefaultCipherSuite>::start(&mut client_rng, password.as_bytes()).unwrap();
        let credential_request_bytes = client_login_start_result.message.serialize().to_vec();

        //println!("Login Request Bytes: {:?}", credential_request_bytes);
        let bytes_vector : Vec<u8> = vec![1]; // Represents this is a login operation
        stream.write_all(&bytes_vector).unwrap();
        write_to_stream(&stream, &credential_request_bytes);
        let username_bytes = username.as_bytes().to_vec();
        //println!("Username Bytes: {:?}", username_bytes);
        write_to_stream(&stream, &username_bytes);

        //Read Login Response
        let credential_response_buffer = read_from_stream(&stream);
        //println!("Crdential Response Buffer: {:?}", credential_response_buffer);
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
        let credential_finalization_bytes = client_login_finish_result.message.serialize().to_vec();
        //println!("Credential Finalization Bytes: {:?}", credential_finalization_bytes);
        //println!("Credential Finalization Length: {}", credential_finalization_length);
        //println!("Credential Finalization Length Byte: {:?}", credential_finalization_length_vector);
        write_to_stream(&stream, &credential_finalization_bytes);
        //println!("Encrypted Ciphertext Length Bytes: {:?}", length_buffer);
        //println!("Encrypted Ciphertext Length: {}", length);
        let encrypted_ciphertext = read_from_stream(&stream);
        //println!("Encrypted Ciphertext: {:?}", encrypted_ciphertext);
        let ciphertext = decrypt(&client_login_finish_result.session_key,
            &encrypted_ciphertext,);
        //println!("Ciphertext: {:?}", ciphertext);
        let plaintext = decrypt(
            &client_login_finish_result.export_key,
            &ciphertext,
        );
        Ok(plaintext)
    }

fn close_connection(mut stream: TcpStream) {
    stream.write_all(&vec![2]).unwrap();
}

fn generate_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = thread_rng();

    let random_string: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    random_string
}

fn main() {
    //let mut length = 64;
    //println!("{:?}", u32_to_bytes(length));
    //println!("{:?}", bytes_to_u32(u32_to_bytes(length)));
    let mut rng = OsRng;

    let num_strings = 500; // Number of random strings to generate
    let string_length = 20; // Length of each random string
    let n_workers = 10;
    let pool = ThreadPool::new(n_workers);
    // Generate an array of random strings
    let mut random_passwords: Vec<String> = Vec::with_capacity(num_strings);
    let mut random_usernames: Vec<String> = Vec::with_capacity(num_strings);
    let mut random_keys: Vec<u64> = Vec::with_capacity(num_strings);
    for _ in 0..num_strings {
        random_passwords.push(generate_random_string(string_length));
        random_usernames.push(generate_random_string(string_length));
        random_keys.push(rng.gen::<u64>());
    }
    let mut start_time = Instant::now();
    for task_id in 0..num_strings {
        // Spawn a new thread for each task
        let username = random_usernames[task_id].to_string();
        let password = random_passwords[task_id].clone();
        let key = random_keys[task_id].to_string();
        pool.execute(move || {
            if let Ok(stream) = TcpStream::connect("127.0.0.1:7878") {
                let  register_stream = stream.try_clone().unwrap();
                let  shutdown_stream = stream.try_clone().unwrap();
                //println!("Connected to the server!");
                register(register_stream, username, password, key);
                close_connection(shutdown_stream);
                stream.shutdown(Shutdown::Both).unwrap();
            } else {
                println!("Couldn't connect to server...");
            }
        });
    }
    pool.join();
    let mut end_time = Instant::now();
    let mut elapsed = end_time.duration_since(start_time);
    println!("Elapsed time for running {} register operations on {} worker threads: {:?}",num_strings, n_workers, elapsed);
    
    start_time = Instant::now();
    for task_id in 0..num_strings {
        // Spawn a new thread for each task
        let username = random_usernames[task_id].to_string();
        let password = random_passwords[task_id].clone();
        let key = random_keys[task_id].to_string();
        pool.execute(move || {
            if let Ok(stream) = TcpStream::connect("127.0.0.1:7878") {
                let  login_stream = stream.try_clone().unwrap();
                let  shutdown_stream = stream.try_clone().unwrap();
                // println!("Connected to the server!");
                println!("Task {} Retrieved Key: {:?}",task_id, login(login_stream, username, password).unwrap());
                //login(login_stream, username, password).unwrap();
                println!("Task {} Actual Key: {:?}",task_id, key.as_bytes());
                close_connection(shutdown_stream);
                //stream.shutdown(Shutdown::Both).unwrap();
            } else {
                println!("Couldn't connect to server...");
            }
        });
    }
    pool.join();
    end_time = Instant::now();
    elapsed = end_time.duration_since(start_time);
    println!("Elapsed time for running {} Login operations on {} worker threads: {:?}",num_strings, n_workers, elapsed);

    // if let Ok(mut stream) = TcpStream::connect("127.0.0.1:7878") {
    //     let mut register_stream = stream.try_clone().unwrap();
    //     let mut login_stream = stream.try_clone().unwrap();
    //     let mut shutdown_stream = stream.try_clone().unwrap();
    //     println!("Connected to the server!");
    //     let mut start_time = Instant::now();
    //     register(register_stream, "leo".to_string(), "123456".to_string(), "hello world".to_string());
    //     let mut end_time = Instant::now();
    //     let mut elapsed = end_time.duration_since(start_time);
    //     println!("Register Takes: {:?}", elapsed);
    //     start_time = Instant::now();
    //     println!("{}", login(login_stream, "leo".to_string(), "123456".to_string()).unwrap());
    //     end_time = Instant::now();
    //     elapsed = end_time.duration_since(start_time);
    //     println!("Login Takes: {:?}", elapsed);
    //     close_connection(shutdown_stream);
    //     stream.shutdown(Shutdown::Both);
    // } else {
    //     println!("Couldn't connect to server...");
    // }
}