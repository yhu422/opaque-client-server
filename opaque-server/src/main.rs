use std::{
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
};
use opaque_ke::{
    CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationRequestLen, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginStartParameters, ServerRegistration, ServerRegistrationLen, ServerSetup,
};

fn handle_register(){
    println!("I am registering");
}

fn handle_retrieve(){
    println!("I am retrieving");
}

fn handle_connection(mut stream: TcpStream){
    let mut buf_reader = BufReader::new(&mut stream);
    let buffer = buf_reader.fill_buf().unwrap();
    let request_type = buffer[0];
    if buffer[0] == 1 {
       //Handle Registration
    }else {
       //Handle Login
    }
    let length = buffer.len();
    buf_reader.consume(length);
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        handle_connection(stream);
    }
}
