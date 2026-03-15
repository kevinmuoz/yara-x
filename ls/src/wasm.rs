// Wasm-specific entry points for the YARA language server.

use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use futures::io::{AsyncRead, AsyncWrite};
use futures::{Sink, Stream, StreamExt};
use futures_channel::mpsc::{UnboundedReceiver, unbounded};
use js_sys::JSON;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent};
use ws_stream_wasm::*;

struct WsReader<S> {
    stream: S,
    buffer: Vec<u8>,
}

struct WsWriter<S> {
    sink: S,
    buffer: Vec<u8>,
}

struct WorkerReader {
    receiver: UnboundedReceiver<Vec<u8>>,
    buffer: Vec<u8>,
}

struct WorkerWriter {
    scope: DedicatedWorkerGlobalScope,
    buffer: Vec<u8>,
}

impl<S: Stream<Item = WsMessage> + Unpin> AsyncRead for WsReader<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.buffer.is_empty() {
            match self.stream.poll_next_unpin(cx) {
                Poll::Ready(Some(msg)) => {
                    let data = match msg {
                        WsMessage::Binary(data) => data,
                        WsMessage::Text(text) => text.into_bytes(),
                    };
                    let header =
                        format!("Content-Length: {}\r\n\r\n", data.len());
                    self.buffer.extend_from_slice(header.as_bytes());
                    self.buffer.extend_from_slice(&data);
                }
                Poll::Ready(None) => return Poll::Ready(Ok(0)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let len = std::cmp::min(buf.len(), self.buffer.len());
        buf[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Poll::Ready(Ok(len))
    }
}

impl<S: Sink<WsMessage, Error = WsErr> + Unpin> AsyncWrite for WsWriter<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.buffer.extend_from_slice(buf);

        if let Some(text) = take_lsp_message(&mut self.buffer) {
            match Pin::new(&mut self.sink).poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    if let Err(err) =
                        Pin::new(&mut self.sink).start_send(WsMessage::Text(text))
                    {
                        return Poll::Ready(Err(std::io::Error::other(
                            err.to_string(),
                        )));
                    }
                }
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Err(std::io::Error::other(
                        err.to_string(),
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.sink)
            .poll_flush(cx)
            .map_err(|err| std::io::Error::other(err.to_string()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.sink)
            .poll_close(cx)
            .map_err(|err| std::io::Error::other(err.to_string()))
    }
}

impl AsyncRead for WorkerReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.buffer.is_empty() {
            match self.receiver.poll_next_unpin(cx) {
                Poll::Ready(Some(data)) => {
                    let header =
                        format!("Content-Length: {}\r\n\r\n", data.len());
                    self.buffer.extend_from_slice(header.as_bytes());
                    self.buffer.extend_from_slice(&data);
                }
                Poll::Ready(None) => return Poll::Ready(Ok(0)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let len = std::cmp::min(buf.len(), self.buffer.len());
        buf[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Poll::Ready(Ok(len))
    }
}

impl AsyncWrite for WorkerWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.buffer.extend_from_slice(buf);

        if let Some(text) = take_lsp_message(&mut self.buffer) {
            let payload =
                JSON::parse(&text).unwrap_or_else(|_| JsValue::from_str(&text));

            self.scope
                .post_message(&payload)
                .map_err(|err| std::io::Error::other(format!("{err:?}")))?;
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

fn parse_content_length(header_buf: &[u8]) -> Option<usize> {
    let header_str = std::str::from_utf8(header_buf).ok()?;
    for line in header_str.lines() {
        if line.to_ascii_lowercase().starts_with("content-length:") {
            return line.split(':').nth(1)?.trim().parse().ok();
        }
    }
    None
}

fn take_lsp_message(buffer: &mut Vec<u8>) -> Option<String> {
    let pos = find_header_end(buffer)?;
    let content_length = parse_content_length(&buffer[..pos])?;
    let total_required = pos + 4 + content_length;

    if buffer.len() < total_required {
        return None;
    }

    let body = buffer[pos + 4..total_required].to_vec();
    buffer.drain(..total_required);
    Some(String::from_utf8_lossy(&body).into_owned())
}

// TODO: This method was deleted recently from upstream main, have to re-add it
pub async fn run_server(url: String) -> Result<(), JsValue> {
    console_error_panic_hook::set_once();

    let (_ws, wsio) = WsMeta::connect(&url, None)
        .await
        .map_err(|err| JsValue::from(err.to_string()))?;

    let (sink, stream) = wsio.split();
    let input = WsReader {
        stream,
        buffer: Vec::new(),
    };
    let output = WsWriter {
        sink,
        buffer: Vec::new(),
    };

    spawn_local(async move {
        if let Err(err) = crate::serve(input, output).await {
            web_sys::console::error_1(&err.to_string().into());
        }
    });

    Ok(())
}

#[wasm_bindgen(js_name = "runWorkerServer")]
pub fn run_worker_server() -> Result<(), JsValue> {
    console_error_panic_hook::set_once();

    let scope: DedicatedWorkerGlobalScope = js_sys::global()
        .dyn_into()
        .map_err(|_| JsValue::from_str("runWorkerServer must run in a workre"))?;

    let (sender, receiver) = unbounded::<Vec<u8>>();
    let sender = Rc::new(RefCell::new(sender));

    let onmessage =
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let text = if let Some(text) = event.data().as_string() {
                text
            } else {
                JSON::stringify(&event.data())
                    .ok()
                    .and_then(|value| value.as_string())
                    .unwrap_or_default()
            };

            let _ = sender.borrow_mut().unbounded_send(text.into_bytes());
        });

    scope.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    let input = WorkerReader {
        receiver,
        buffer: Vec::new(),
    };
    let output = WorkerWriter {
        scope,
        buffer: Vec::new(),
    };

    spawn_local(async move {
        if let Err(err) = crate::serve(input, output).await {
            web_sys::console::error_1(&err.to_string().into());
        }
    });

    Ok(())
}
