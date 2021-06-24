use std::sync::Arc;
use lazy_static::lazy_static;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tokio::sync::oneshot::{Sender, Receiver};
use warp::{Filter, http, http::Response, reject, reply};
use webbrowser;
use std::net::TcpListener;
use std::io::{BufReader, BufRead, Write};
use reqwest::{Url, Error};


static CLIENT_ID: &str = "85fdd8c6-5642-420e-bb72-ad6e7178b404";


#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorizationData {
    code: String,
    state: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Token {
    access_token: String,
    token_type: String,
    expires_in: i32,
    scope: String,
    id_token: String,
}


impl AuthorizationData {
    pub fn new() -> AuthorizationData {
        return AuthorizationData {
            code: String::new(),
            state: String::new(),
        };
    }
}

pub async fn get_token(data: AuthorizationData) -> Result<Token, Error> {
    let client = reqwest::Client::new();
    let res = client.post("https://login.microsoftonline.com/common/oauth2/v2.0/token")
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!("\
        client_id={}\
        &scope=openid\
        &code={}\
        &redirect_uri={}\
        &grant_type=authorization_code\
        &code_verifier=YTFjNjI1OWYzMzA3MTI4ZDY2Njg5M2RkNmVjNDE5YmE", CLIENT_ID, data.code, "http://localhost:8080/todo/"))
        .send()
        .await?;
    let tok = res.json::<Token>().await.unwrap();
    dbg!(&tok);
    Ok(tok)
}

pub async fn authenticate() -> Result<Token, Error> {

    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    let mut auth_data = AuthorizationData::new();
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let mut reader = BufReader::new(&stream);

            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();

            let url_code = request_line.split_whitespace().nth(1).unwrap();

            let url = Url::parse(&("http://localhost".to_string() + url_code)).unwrap();

            let code_pair = url
                .query_pairs()
                .find(|pair| {
                    let &(ref key, _) = pair;
                    key == "code"
                })
                .unwrap();

            let (_, value) = code_pair;
            auth_data.code = value.to_string();

            let state_pair = url
                .query_pairs()
                .find(|pair| {
                    let &(ref key, _) = pair;
                    key == "state"
                })
                .unwrap();

            let (_, value) = state_pair;
            auth_data.state = value.to_string();

            let message = "Go back to your terminal :)";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                message.len(),
                message
            );
            stream.write_all(response.as_bytes()).unwrap();
            break;
        }
    }
    Ok(get_token(auth_data).await?)
}

#[tokio::main]
async fn main() -> () {
    let request_url = format!("\
    https://login.microsoftonline.com/common/oauth2/v2.0/authorize?\
    client_id={}&response_type=code\
    &redirect_uri={}&scope=openid&\
    response_mode=query&state=12345&nonce=678910\
    &code_challenge=YTFjNjI1OWYzMzA3MTI4ZDY2Njg5M2RkNmVjNDE5YmE\
    &code_challenge_method=plain", CLIENT_ID, "http://localhost:8080/todo/");


    if webbrowser::open(&request_url).is_ok() {
        let auth_token = authenticate().await;
        if let Ok(token) = auth_token {
            dbg!(token);
        }
    }
}
