use fastly::http::{Method, StatusCode, header};
use fastly::http::header::{CONTENT_LENGTH, HOST};
use fastly::{Error, Request, Response};
use std::io::Write;

use m3u8_rs::playlist::{Playlist, MasterPlaylist, MediaPlaylist};

/// This should be changed to match the name of your own backend. See the the `Hosts` section of
/// the Fastly WASM service UI for more information.
const BACKEND_NAME: &str = "backend_name";

/// The entrypoint for your application
///
/// This function is triggered when your service receives a client request, and
/// should ultimately call `send_downstream` on a fastly::Response to deliver an
/// HTTP response to the client.
#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    // set up logging first
    fastly::log::set_panic_endpoint("mylogs").unwrap();

    // Filter request methods...
    match req.get_method() {
        // Allow GET and HEAD requests.
        &Method::GET | &Method::HEAD => (),

        // Accept PURGE requests; it does not matter to which backend they are sent.
        m if m == "PURGE" => return Ok(req.send(BACKEND_NAME)?),

        // Deny anything else.
        _ => {
            return Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
                .with_header(header::ALLOW, "GET, HEAD")
                .with_body_text_html("This method is not allowed\n"))
        }
    };

    // we need to keep req path to build ACL if manifest has relative paths
    let req_url_path = req.get_path().to_string();

    let mut endpoint = fastly::log::Endpoint::from_name("mylogs");

    match req.send(BACKEND_NAME) {
        Ok(mut beresp) if beresp.get_status().is_success() => {

            // consume the original response body
            let bytes = beresp.take_body_bytes();

            let resp = match m3u8_rs::parse_playlist_res(&bytes) {
                Ok(Playlist::MasterPlaylist(mut pl)) => master_token(&mut pl, beresp, req_url_path)?,
                Ok(Playlist::MediaPlaylist(mut pl)) => media_token(&mut pl, beresp, req_url_path)?,
                Err(_) => {
                    Response::from_status(StatusCode::INTERNAL_SERVER_ERROR)
                        .with_body("The manifest is not recognized")
                }
            };
            Ok(resp)
        }

        Ok(resp) => {
            writeln!(endpoint, "{} path didn't work", req_url_path).unwrap();
            Ok(resp)
        }

        Err(e) => {
            writeln!(endpoint, "Err(e) - {:?}", e).unwrap();
            let resp = Response::from_status(StatusCode::INTERNAL_SERVER_ERROR);
            Ok(resp)
        }
    }
}

fn master_token(pl: &mut MasterPlaylist,
                mut beresp: Response,
                req_url_path : String) -> Result<Response, Error> {

    let now = get_epoch();
    for varient in &mut pl.variants {
        varient.uri = set_token(now, varient.uri.to_string(), &req_url_path);
    }
    let mut resp_body = vec![];

    pl.write_to(&mut resp_body).unwrap();

    beresp.set_body(resp_body);

    Ok(beresp)
}

fn media_token(pl: &mut MediaPlaylist,
               mut resp: Response,
               req_url_path : String) -> Result<Response, Error>  {

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

    resp.set_body(resp_body);

    Ok(resp)
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
    let acl;

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
        Regex::new(r"^(?:(?P<proto>(?:https?)://)(?P<host>[^/]+))?(?P<dirname>/?.*?/)?(?P<basename>[^/]+?)?(?P<qs>\?.*)?$").unwrap();
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
