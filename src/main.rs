use fastly::http::{HeaderValue, Method, StatusCode};
use fastly::http::header::{CONTENT_LENGTH, HOST};
use fastly::http::response::Parts;
use fastly::{downstream_request, Body, Error, Request, RequestExt, Response, ResponseExt};

use std::convert::{TryFrom};
use std::io::Write;

use m3u8_rs::playlist::{Playlist, MasterPlaylist, MediaPlaylist};

const VALID_METHODS: [Method; 3] = [
    Method::HEAD,
    Method::GET,
    Method::POST
];

/// Handle the downstream request from the client.
///
/// This function accepts a Request<Body> and returns a Response<Body>. It could
/// be used to route based on the request properties (such as method or path),
/// send the request to a backend, make completely new requests and/or generate
/// synthetic responses.
fn handle_request(mut req: Request<Body>) -> Result<Response<Body>, Error> {

    if !(VALID_METHODS.contains(req.method())) {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::try_from("This method is not allowed")?)?);
    }

    // Pattern match on the request method and path.
//    match (req.method(), req.uri().path()) {
//        (&Method::GET, path) if path.ends_with("m3u8") => {
    match req.method() {
        &Method::GET => {

            // Just set the TTL cache override
            req.set_pass();

            Ok(req.send("dai-backend")?)
        }

        // Catch all other requests and return a 404.
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::try_from("The page you requested could not be found")?)?),
    }
}

/// The entrypoint for your application
///
/// This function is triggered when your service receives a client request, and
/// should ultimately call `send_downstream` on a fastly::Response to deliver an
/// HTTP response to the client.
fn main() -> Result<(), Error> {
    // set up logging first
    fastly::log::set_panic_endpoint("mylogs").unwrap();

    // get request from downstream
    let req = downstream_request();

    // we need to keep req path to build ACL if manifest has relative paths
    let req_url_path = req.uri().path().to_string();

    let mut endpoint = fastly::log::Endpoint::from_name("mylogs");

    match handle_request(req) {
        Ok(beresp) if beresp.status().is_success() => {
            let (beresp_meta, beresp_body) = beresp.into_parts();
            let bytes = beresp_body.into_bytes();

            match m3u8_rs::parse_playlist_res(&bytes) {
                Ok(Playlist::MasterPlaylist(mut pl)) => master_token(&mut pl, beresp_meta, req_url_path)?,
                Ok(Playlist::MediaPlaylist(mut pl)) => media_token(&mut pl, beresp_meta, req_url_path)?,
                Err(_) => {
                    let resp = Response::builder()
                        .status(StatusCode::METHOD_NOT_ALLOWED)
                        .body(Body::try_from("Oopsy-daisy")?)?;
                    resp.send_downstream_streaming();
                }
            }
        }

        Ok(beresp) => {
            writeln!(endpoint, "req_url_path - {}", req_url_path).unwrap();
            writeln!(endpoint, "Didn't work").unwrap();
            beresp.send_downstream();
        }

        Err(e) => {
            writeln!(endpoint, "Err(e) - {}", e).unwrap();
            let mut resp = Response::new(e.to_string());
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            resp.send_downstream();
        }
    }
    Ok(())
}

fn master_token(pl: &mut MasterPlaylist,
                mut meta: Parts,
                req_url_path : String) -> Result<(), Error> {

    let now = get_epoch();
    for varient in &mut pl.variants {
        varient.uri = set_token(now, varient.uri.to_string(), &req_url_path);
    }
    let mut resp_body = vec![];

    pl.write_to(&mut resp_body).unwrap();

    let resp_http_content_length: String = resp_body.len().to_string();

    meta.headers.remove(CONTENT_LENGTH);
    meta.headers.insert(CONTENT_LENGTH,
                        HeaderValue::from_str(&resp_http_content_length).unwrap());

    let resp = Response::from_parts(meta, resp_body);

    resp.send_downstream();

    Ok(())
}

fn media_token(pl: &mut MediaPlaylist,
               mut meta: Parts,
               req_url_path : String) -> Result<(), Error>  {

    let now = get_epoch();
    for segment in &mut pl.segments {
        segment.uri = set_token(now, segment.uri.to_string(), &req_url_path);
        if segment.key.is_some() {
            let mut k = segment.key.clone().unwrap();
            if k.uri.is_some() {
                k.uri = Some(set_token(now, k.uri.unwrap(), &req_url_path));
            }
            segment.key = Some(k);
        }
    }
    let mut resp_body = vec![];

    pl.write_to(&mut resp_body).unwrap();

    let resp_http_content_length: String = resp_body.len().to_string();

    meta.headers.remove(CONTENT_LENGTH);
    meta.headers.insert(CONTENT_LENGTH,
                        HeaderValue::from_str(&resp_http_content_length).unwrap());

    let resp = Response::from_parts(meta, resp_body);

    resp.send_downstream();

    Ok(())
}

fn get_epoch() ->u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}


fn set_token(unix_time: u64, url: String, req_url_path: &str) -> String {

    use sha2::Sha256;
    use hmac::{Hmac, Mac, NewMac};

    let secret = &base64::decode("c2VjcmV0").unwrap()[..];

    let st = &unix_time;
    let expiration = &unix_time + 60*60*24*30;
    let exp = expiration.to_string();

    // get parts of the URL/URI
    let (proto, host, dirname, basename, mut qs) = get_parts(&url);

    // if not our domain(s) - return as is
    if (host != "") && (host != "dai.example.com") {
        return url.to_string();
    }

    let uri_path = format!("{}{}", dirname, basename);
    let mut acl;

    // if the path is not relative
    // we need to add the working directory from the _this_ request
    // to construct the proper ACL
    if dirname.starts_with("/") {
        acl = format!("{}{}", dirname, basename);
    } else {
        let (_, _, req_dirname, _, _) = get_parts(&req_url_path);
        acl = format!("{}{}{}", req_dirname, dirname, basename);
    }

    let string_to_sign = format!("st={}~exp={}~acl={}", st, exp, acl);

    // Create alias for HMAC-SHA256
    type HmacSha256 = Hmac<Sha256>;

    // Create HMAC-SHA256 instance which implements `Mac` trait
    let mut mac = HmacSha256::new_varkey(secret)
        .expect("HMAC can take key of any size");
    mac.update(string_to_sign.as_bytes());

    // `result` has type `MacResult` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    let result = mac.finalize();
    let hmac = result.into_bytes();

    let token = format!("hdnts=st={}~exp={}~acl={}~hmac={}",st,exp,acl,hex::encode(hmac));

    // deal with query string
    if qs == "" {
        qs = "?".to_string();
    } else {
        qs.push_str("&");
    }

    format!("{}{}{}{}{}", proto, host, uri_path, qs, token)
}

#[macro_use]
extern crate lazy_static;
extern crate regex;
use regex::Regex;
//use std::intrinsics::exact_div;

// returns tuple:
//  (proto, host,  dirname,  basename,  qs)
//
fn get_parts(url: &str) -> (String, String, String, String, String) {
    lazy_static! {
        static ref RE: Regex =
        Regex::new(r"^(?:(?P<proto>(?:http|https)://)(?P<host>[^/]+))?(?P<dirname>/?.*?/)?(?P<basename>[^/]+?)?(?P<qs>\?.*)?$").unwrap();
    }
    let caps = RE.captures(url).unwrap();

    let proto = caps.name("proto").map_or("", |proto| proto.as_str());
    let host = caps.name("host").map_or("", |host| host.as_str());
    let dirname = caps.name("dirname").map_or("", |dirname| dirname.as_str());
    let basename = caps.name("basename").map_or("", |basename| basename.as_str());
    let qs = caps.name("qs").map_or("", |qs| qs.as_str());

    return (proto.to_string(),
            host.to_string(),
            dirname.to_string(),
            basename.to_string(),
            qs.to_string()
    );
}
