use std::{
    io::{prelude::*, Write, Read},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    collections::HashMap
};
use rand::rngs::OsRng;
use rand::{Rng, RngCore, thread_rng};
use generic_array::GenericArray;
use opaque_ke::{ CipherSuite,
    CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationRequestLen, RegistrationResponseLen, RegistrationUpload, ServerLogin,
    ServerLoginStartParameters, ServerRegistration, ServerRegistrationLen, ServerSetup,
};

struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

struct Locker {
    guess_count: u8,
    contents: Vec<u8>,
    password_file: GenericArray<u8, ServerRegistrationLen<DefaultCipherSuite>>,
}


fn handle_retrieve(){
    println!("I am retrieving");
}

fn handle_connection(mut stream: TcpStream, mut registered_lockers: &Arc<Mutex<HashMap<String, Locker>>>){
    let mut type_buffer: [u8; 1] = [0];
    let mut length_buffer: [u8; 4] = [0,0,0,0];
    let mut rng = OsRng;
    let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);
    stream.read_exact(&mut type_buffer);
    if type_buffer[0] == 0 {
        stream.read_exact(&mut length_buffer);
        let mut length: usize = 0;

        for byte in length_buffer {
            length = (length << 8) | byte as usize;
        }
        //println!("{}", length);
        let mut registration_request_buffer = vec![0;length];
        stream.read_exact(&mut registration_request_buffer);
        stream.read_exact(&mut length_buffer);
        length = 0;
        for byte in length_buffer {
            length = (length << 8) | byte as usize;
        }
        let mut username_buffer = vec![0;length];
        stream.read_exact(&mut username_buffer);
        println!("Registration Request Bytes: {:?}", registration_request_buffer);
        println!("Username Bytes: {:?}", username_buffer);
        let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
            &server_setup,
            RegistrationRequest::deserialize(&registration_request_buffer).unwrap(),
            &b"RANDOM_STRING".to_vec(),
        ).unwrap();

        //Prepare sending registration response
        let registration_response_bytes = server_registration_start_result.message.serialize();
        println!("Registration Response Bytes: {:?}", registration_response_bytes);
        length = registration_response_bytes.len();
        println!("Registration Response Length: {}", length);
        let mut length_vector : Vec<u8> = Vec::with_capacity(4);
        for i in (0..4).rev() {
            // Extract individual bytes using bitwise operations
            let byte = ((length >> (i * 8)) & 0xFF) as u8;
            length_vector.push(byte);
        }
        println!("Registration Response Length Bytes: {:?}", length_vector);
        length_vector.extend(registration_response_bytes);
        stream.write_all(&length_vector); 
        stream.flush();
        // In a real setting, a signature over the registration response bytes and a Challenge will also be sent. Omitted for simplicity

        stream.read_exact(&mut length_buffer);
        println!("Length Buffer: {:?}", length_buffer);
        length = 0;
        for byte in length_buffer {
            length = (length << 8) | byte as usize;
        }
        println!("Ciphertext Buffer Length: {}", length);
        let mut ciphertext_buffer = vec![0;length];
        stream.read_exact(&mut ciphertext_buffer);
        println!("CipherText: {:?}", ciphertext_buffer);
        stream.read_exact(&mut length_buffer);
        length = 0;
        for byte in length_buffer {
            length = (length << 8) | byte as usize;
        }
        println!("Registration Result Buffer Length: {}", length);
        let mut registration_result_buffer = vec![0;length];
        stream.read_exact(&mut registration_result_buffer);
        println!("Registration Result Buffer: {:?}", registration_result_buffer);
        let password_file = ServerRegistration::finish(
            RegistrationUpload::<DefaultCipherSuite>::deserialize(&registration_result_buffer).unwrap(),
        );
        
        let l = Locker {
            guess_count: 10,
            contents: ciphertext_buffer,
            password_file: password_file.serialize(),
        };
        let mut m = registered_lockers.lock().unwrap();
        m.insert(String::from_utf8(username_buffer).unwrap(), l);
    }else {
        stream.read_exact(&mut length_buffer);
        let mut length: usize = 0;

        for byte in length_buffer {
            length = (length << 8) | byte as usize;
        }
        //println!("{}", length);
        let mut credential_request_buffer = vec![0;length];
        stream.read_exact(&mut credential_request_buffer);
        stream.read_exact(&mut length_buffer);
        length = 0;
        for byte in length_buffer {
            length = (length << 8) | byte as usize;
        }
        let mut username_buffer = vec![0;length];
        stream.read_exact(&mut username_buffer);
        println!("Login Request Bytes: {:?}", credential_request_buffer);
        println!("Username Bytes: {:?}", username_buffer);        
        let mut m = registered_lockers.lock().unwrap();
        let l = m.get(&String::from_utf8(username_buffer).unwrap());
    }
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
    let registered_lockers = Arc::new(Mutex::new(HashMap::new()));
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        handle_connection(stream, &registered_lockers);
        // let getter = registered_lockers.lock().unwrap();
        // println!("{:?}", getter.get("leo").unwrap().guess_count);
    }
}
