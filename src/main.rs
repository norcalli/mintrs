#![feature(custom_attribute, custom_derive, plugin)]
#![plugin(serde_macros)]
#![feature(time2)]

#[macro_use]
extern crate hyper;
extern crate url;

extern crate serde;
extern crate serde_json;
extern crate eventual;

extern crate docopt;

use hyper::Client;
use hyper::header::{ContentType, Connection};
use url::form_urlencoded as urlencode;
use std::collections::HashMap;

use hyper::header::{Authorization, Bearer, Accept, qitem};
use hyper::header::{CookieJar, SetCookie, Cookie};
use hyper::mime::Mime;

use serde_json::{Value, to_value};

use std::io::Read;

use std::time::{Instant, SystemTime, UNIX_EPOCH, Duration};

struct Mint {
    client: Client,
    cj: CookieJar<'static>,
    login_data: LoginData,
    oauth_token: OAuthToken,
    login_time: Instant,
}

#[derive(Default, Serialize, Deserialize, Debug)]
struct LoginData {
    username: String,
    token: String,
}


#[derive(Default, Deserialize, Debug)]
struct OAuthToken {
    access_token: String,
    expires: u64,
}

impl LoginData {
    fn from_value(value: &Value) -> Option<LoginData> {
        value.find("sUser").and_then(|s_user| {
            match (s_user.find("username").and_then(Value::as_string),
                   s_user.find("token").and_then(Value::as_string)) {
                (Some(username), Some(token)) => {
                    Some(LoginData {
                        username: String::from(username),
                        token: String::from(token),
                    })
                }
                _ => None,
            }
        })
    }
}

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref ACCEPT_JSON: Accept = {
        let mime: Mime = "application/json".parse().unwrap();
        Accept(vec![qitem(mime)])
    };
}

use std::error::Error;

#[derive(Debug)]
enum MintError {
    ExpiredSession,
    InvalidLogin,
    Unauthorized,
    UnknownError(Box<Error>),
}

macro_rules! unknown_error (
    ($name: ty) => {
        impl From<$name> for MintError {
            fn from(err: $name) -> MintError {
                MintError::UnknownError(From::from(err))
            }
        }
    }
);

unknown_error!(std::time::SystemTimeError);
unknown_error!(serde_json::Error);
unknown_error!(hyper::Error);
unknown_error!(std::io::Error);

impl Mint {
    fn new() -> Mint {
        Mint {
            client: Client::new(),
            cj: CookieJar::new(b"mint"),
            login_data: Default::default(),
            oauth_token: Default::default(),
            login_time: Instant::now(),
        }
    }

    fn post<U: hyper::client::IntoUrl>(&self, url: U) -> hyper::client::RequestBuilder {
        self.client
            .post(url)
            .header(ACCEPT_JSON.clone())
            // .header(Authorization(Bearer { token: self.oauth_token.access_token.clone() }))
            .header(Cookie::from_cookie_jar(&self.cj))
    }

    fn get<U: hyper::client::IntoUrl>(&self, url: U) -> hyper::client::RequestBuilder {
        self.client
            .get(url)
            .header(ACCEPT_JSON.clone())
            // .header(Authorization(Bearer { token: self.oauth_token.access_token.clone() }))
            .header(Cookie::from_cookie_jar(&self.cj))
    }

    fn auth_post<U: hyper::client::IntoUrl>(&self, url: U) -> hyper::client::RequestBuilder {
        self.post(url)
            .header(Authorization(Bearer { token: self.oauth_token.access_token.clone() }))
    }

    fn auth_get<U: hyper::client::IntoUrl>(&self, url: U) -> hyper::client::RequestBuilder {
        self.get(url)
            .header(Authorization(Bearer { token: self.oauth_token.access_token.clone() }))
    }

    fn set_cookies(&mut self, headers: &hyper::header::Headers) {
        headers.get::<SetCookie>().unwrap().apply_to_cookie_jar(&mut self.cj);
    }

    fn get_new_session(&mut self) -> Result<(), MintError> {
        {
            let body = urlencode::serialize(&[("clientType", "Mint"),
            ("username", &self.login_data.username)]);
            let res = try!(self.post("https://wwws.mint.com/getUserPod.xevent")
                           .header(ContentType::form_url_encoded())
                           .body(&body)
                           .send());
            self.set_cookies(&res.headers);
        }
        self.login_time = Instant::now();
        Ok(())
    }

    fn get_new_token(&mut self) -> Result<(), MintError> {
        {
            let mut req_url = url::Url::parse("https://wwws.mint.com/oauth2.xevent")
                                  .expect("Parse url");

            let now = try!(UNIX_EPOCH.elapsed()).as_secs();
            req_url.set_query_from_pairs(&[("token", &self.login_data.token),
                                           ("_", &now.to_string())]);

            // GET /oauth2.xevent?token=TOKEN&_=1450136574374 HTTP/1.1
            // Host: wwws.mint.com
            let mut res = try!(self.get(req_url).send());
            let mut buffer = String::new();
            try!(res.read_to_string(&mut buffer));

            if buffer.contains("Session has expired.") {
                return Err(MintError::ExpiredSession);
            }
            // let token: OAuthToken = serde_json::from_reader(res).expect("Failed to deserialize");
            self.oauth_token = try!(serde_json::from_str(&buffer));
        }
        Ok(())
    }

    fn expired(&self) -> bool {
        Instant::now().duration_from_earlier(self.login_time).as_secs()*1000 > self.oauth_token.expires
    }

    fn login(username: &str, password: &str) -> Result<Mint, MintError> {
        let mut mint = Mint::new();
        mint.login_data.username = String::from(username);

        // {
        //     let body = urlencode::serialize(&[("clientType", "Mint"), ("username", username)]);
        //     let res = try!(mint.post("https://wwws.mint.com/getUserPod.xevent")
        //                    .header(ContentType::form_url_encoded())
        //                    .body(&body)
        //                    .send());
        //     mint.set_cookies(&res.headers);
        //     println!("{:?}", Cookie::from_cookie_jar(&mint.cj));
        // }

        try!(mint.get_new_session());
        {
            let body = urlencode::serialize(&[("task", "L"),
                                              ("username", username),
                                              ("password", password),
                                              ("browser", "chrome"),
                                              ("browserVersion", "47"),
                                              ("os", "mac")]);

            let res = try!(mint.post("https://wwws.mint.com/loginUserSubmit.xevent")
                               .header(ContentType::form_url_encoded())
                               .body(&body)
                               .send());

            mint.set_cookies(&res.headers);

            let deserialized: Value = try!(serde_json::from_reader(res));
            mint.login_data = try!(LoginData::from_value(&deserialized)
                                       .ok_or(MintError::InvalidLogin));
        }
        try!(mint.get_new_token());
        Ok(mint)
    }

    fn accounts(&self) -> Result<Value, MintError> {
        static URL: &'static str = "https://mint.finance.intuit.com/v1/accounts?limit=100";
        let res = try!(self.auth_get(URL)
                       .header(Connection::close())
                       .send());
        if res.status == hyper::status::StatusCode::Unauthorized {
            Err(MintError::Unauthorized)
        } else {
            let value: Value = try!(serde_json::from_reader(res));
            Ok(value)
        }
    }
}


use docopt::Docopt;


const USAGE: &'static str = "
Usage:
    mintrs USERNAME PASSWORD
";


fn main() {
    let args = Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .unwrap_or_else(|e| e.exit());
    let mut mint = Mint::login(args.get_str("USERNAME"), args.get_str("PASSWORD"))
                       .expect("Login failed");
    // GET /v1/accounts?limit=100 HTTP/1.1
    // Host: mint.finance.intuit.com
    println!("{:?}, {}", Instant::now().duration_from_earlier(mint.login_time), mint.oauth_token.expires);
    println!("{}", mint.expired());
    println!("{:?}", mint.login_data);
    println!("{:?}", mint.oauth_token);

    // let res = mint.auth_get("https://mint.finance.intuit.com/v1/accounts?limit=100")
    let mut x = 0;
    for _ in eventual::Timer::new().interval_ms(10000).iter() {
        x += 10;
        let result = mint.accounts().expect("Failed to get accounts");
        let result = result.find("Account")
            .and_then(Value::as_array)
            .map(|a| -> Vec<_> { a.iter().map(|x| x.find("value")).collect() });
        println!("Count: {:4}, Expired: {}, Balance: {:?}", x, mint.expired(), result);
    }
}
