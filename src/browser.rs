//! Browser fetch for the outer POST. No cookies, credentials, referrer or
//! caching; redirects are errors. Callers apply their own deadline.
use crate::{
    Error, Result,
    client::{Post, RawReply},
};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

const LIMIT: usize = 1 << 20;

#[derive(Clone, Copy, Debug, Default)]
pub struct FetchPost;

impl Post for FetchPost {
    async fn post(&self, url: &str, content_type: &'static str, body: Vec<u8>) -> Result<RawReply> {
        let window = web_sys::window().ok_or(Error::Transport)?;
        let headers = web_sys::Headers::new().map_err(|_| Error::Transport)?;
        headers
            .set("content-type", content_type)
            .map_err(|_| Error::Transport)?;
        let options = web_sys::RequestInit::new();
        options.set_method("POST");
        options.set_mode(web_sys::RequestMode::Cors);
        options.set_headers(&headers);
        options.set_redirect(web_sys::RequestRedirect::Error);
        options.set_credentials(web_sys::RequestCredentials::Omit);
        options.set_cache(web_sys::RequestCache::NoStore);
        options.set_referrer_policy(web_sys::ReferrerPolicy::NoReferrer);
        options.set_body(&js_sys::Uint8Array::from(body.as_slice()).into());
        let request =
            web_sys::Request::new_with_str_and_init(url, &options).map_err(|_| Error::Transport)?;
        let response: web_sys::Response = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|_| Error::Transport)?
            .dyn_into()
            .map_err(|_| Error::Transport)?;
        let status = response.status();
        let buffer = JsFuture::from(response.array_buffer().map_err(|_| Error::Transport)?)
            .await
            .map_err(|_| Error::Transport)?;
        let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
        if bytes.len() > LIMIT {
            return Err(Error::Transport);
        }
        Ok(RawReply {
            status,
            body: bytes,
        })
    }
}
