//! The screen as guacd draws it: layers, off-screen buffers and the
//! drawing instructions, applied to RGBA images.
//!
//! Supported: `size`, `img`/`blob`/`end` (PNG, JPEG, WebP), `copy`, `rect`
//! with `cfill` and `lfill`, `move`, `shade`, `dispose`. Paths other than
//! rectangles, strokes, clipping and transforms are ignored: guacd's RDP,
//! VNC and terminal output hardly use them. Composite modes other than
//! `SRC` (replace) are drawn as `OVER`.

use std::collections::HashMap;

use base64::Engine;
use image::{imageops, Rgba, RgbaImage};

/// Guacamole's `GUAC_COMP_SRC`: replace, alpha included.
const COMP_SRC: u32 = 0xC;
/// The largest layer or buffer kept, per side.
const MAX_SIDE: u32 = 8192;
/// The most image data one stream may carry.
const MAX_STREAM_BYTES: usize = 32 * 1024 * 1024;
/// How deep nested layers are composited.
const MAX_DEPTH: usize = 16;

struct Layer {
    img: RgbaImage,
    /// Position in the parent, and stacking order among siblings.
    x: i32,
    y: i32,
    z: i32,
    parent: i32,
    opacity: u8,
    /// Rectangles of the current path, for `cfill` / `lfill`.
    path: Vec<(i32, i32, u32, u32)>,
}

impl Layer {
    fn new(w: u32, h: u32) -> Self {
        Layer {
            img: RgbaImage::new(w, h),
            x: 0,
            y: 0,
            z: 0,
            parent: 0,
            opacity: 255,
            path: Vec::new(),
        }
    }
}

struct ImageStream {
    layer: i32,
    mask: u32,
    x: i32,
    y: i32,
    data: Vec<u8>,
}

/// What an instruction asks of the client, beyond drawing.
#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    None,
    /// Answer `sync` with this timestamp: a frame is complete.
    Sync(String),
    /// Refuse a stream the renderer does not take (audio, files, …).
    RefuseStream(String),
    /// guacd ended the connection, or reported an error.
    End(String),
}

#[derive(Default)]
pub struct Display {
    layers: HashMap<i32, Layer>,
    streams: HashMap<String, ImageStream>,
}

fn int(s: Option<&String>) -> i32 {
    s.and_then(|v| v.parse().ok()).unwrap_or(0)
}

fn uint(s: Option<&String>) -> u32 {
    s.and_then(|v| v.parse().ok()).unwrap_or(0)
}

fn blend(dst: &mut Rgba<u8>, src: Rgba<u8>, mask: u32, opacity: u8) {
    let a = (u32::from(src[3]) * u32::from(opacity)) / 255;
    if mask == COMP_SRC && opacity == 255 {
        *dst = src;
        return;
    }
    if a == 0 {
        return;
    }
    let inv = 255 - a;
    let da = u32::from(dst[3]);
    let out_a = a + da * inv / 255;
    for c in 0..3 {
        let s = u32::from(src[c]) * a;
        let d = u32::from(dst[c]) * da * inv / 255;
        dst[c] = (s + d).checked_div(out_a).unwrap_or(0).min(255) as u8;
    }
    dst[3] = out_a.min(255) as u8;
}

/// Draw `src` onto `dst` with its top left at (x, y), clipped.
fn draw(dst: &mut RgbaImage, src: &RgbaImage, x: i32, y: i32, mask: u32, opacity: u8) {
    let (dw, dh) = (dst.width() as i64, dst.height() as i64);
    for sy in 0..src.height() {
        let ty = y as i64 + sy as i64;
        if ty < 0 || ty >= dh {
            continue;
        }
        for sx in 0..src.width() {
            let tx = x as i64 + sx as i64;
            if tx < 0 || tx >= dw {
                continue;
            }
            let p = *src.get_pixel(sx, sy);
            blend(dst.get_pixel_mut(tx as u32, ty as u32), p, mask, opacity);
        }
    }
}

impl Display {
    pub fn new() -> Self {
        let mut d = Display::default();
        d.layers.insert(0, Layer::new(0, 0));
        d
    }

    /// The size of the screen (layer 0).
    pub fn size(&self) -> (u32, u32) {
        self.layers
            .get(&0)
            .map(|l| l.img.dimensions())
            .unwrap_or((0, 0))
    }

    fn layer(&mut self, id: i32) -> &mut Layer {
        self.layers.entry(id).or_insert_with(|| Layer::new(0, 0))
    }

    fn resize(&mut self, id: i32, w: u32, h: u32) {
        let (w, h) = (w.min(MAX_SIDE), h.min(MAX_SIDE));
        let layer = self.layer(id);
        if layer.img.dimensions() == (w, h) {
            return;
        }
        let mut img = RgbaImage::new(w, h);
        imageops::replace(&mut img, &layer.img, 0, 0);
        layer.img = img;
    }

    /// Off-screen buffers (negative ids) grow to hold what is drawn on them.
    fn fit(&mut self, id: i32, x: i32, y: i32, w: u32, h: u32) {
        if id >= 0 || x < 0 || y < 0 {
            return;
        }
        let (cw, ch) = self.layer(id).img.dimensions();
        let (nw, nh) = (cw.max(x as u32 + w), ch.max(y as u32 + h));
        if (nw, nh) != (cw, ch) {
            self.resize(id, nw, nh);
        }
    }

    /// Apply one instruction from guacd.
    pub fn apply(&mut self, opcode: &str, a: &[String]) -> Reply {
        match opcode {
            "size" => {
                self.resize(int(a.first()), uint(a.get(1)), uint(a.get(2)));
            }
            "img" => {
                // img,stream,mask,layer,mimetype,x,y
                let stream = a.first().cloned().unwrap_or_default();
                let mime = a.get(3).map(String::as_str).unwrap_or("");
                if !mime.starts_with("image/") {
                    return Reply::RefuseStream(stream);
                }
                self.streams.insert(
                    stream,
                    ImageStream {
                        mask: uint(a.get(1)),
                        layer: int(a.get(2)),
                        x: int(a.get(4)),
                        y: int(a.get(5)),
                        data: Vec::new(),
                    },
                );
            }
            "blob" => {
                if let Some(s) = a.first().and_then(|id| self.streams.get_mut(id)) {
                    // Each blob is base64 on its own.
                    if let Ok(bytes) = base64::engine::general_purpose::STANDARD
                        .decode(a.get(1).map(String::as_str).unwrap_or(""))
                    {
                        if s.data.len() + bytes.len() <= MAX_STREAM_BYTES {
                            s.data.extend(bytes);
                        }
                    }
                }
            }
            "end" => {
                if let Some(s) = a.first().and_then(|id| self.streams.remove(id)) {
                    self.draw_stream(s);
                }
            }
            "copy" => {
                // copy,srclayer,srcx,srcy,w,h,mask,dstlayer,dstx,dsty
                let (src, sx, sy) = (int(a.first()), int(a.get(1)), int(a.get(2)));
                let (w, h, mask) = (uint(a.get(3)), uint(a.get(4)), uint(a.get(5)));
                let (dst, dx, dy) = (int(a.get(6)), int(a.get(7)), int(a.get(8)));
                self.copy(src, sx, sy, w, h, mask, dst, dx, dy);
            }
            "rect" => {
                let id = int(a.first());
                let r = (int(a.get(1)), int(a.get(2)), uint(a.get(3)), uint(a.get(4)));
                self.layer(id).path.push(r);
            }
            "cfill" => {
                // cfill,mask,layer,r,g,b,a
                let (mask, id) = (uint(a.first()), int(a.get(1)));
                let color = Rgba([
                    uint(a.get(2)).min(255) as u8,
                    uint(a.get(3)).min(255) as u8,
                    uint(a.get(4)).min(255) as u8,
                    uint(a.get(5)).min(255) as u8,
                ]);
                let path = std::mem::take(&mut self.layer(id).path);
                for (x, y, w, h) in path {
                    self.fit(id, x, y, w, h);
                    let mut block = RgbaImage::new(w.min(MAX_SIDE), h.min(MAX_SIDE));
                    block.pixels_mut().for_each(|p| *p = color);
                    draw(&mut self.layer(id).img, &block, x, y, mask, 255);
                }
            }
            "lfill" => {
                // lfill,mask,layer,srclayer: tile the source over the path.
                let (mask, id, src) = (uint(a.first()), int(a.get(1)), int(a.get(2)));
                let path = std::mem::take(&mut self.layer(id).path);
                let Some(tile) = self.layers.get(&src).map(|l| l.img.clone()) else {
                    return Reply::None;
                };
                if tile.width() == 0 || tile.height() == 0 {
                    return Reply::None;
                }
                for (x, y, w, h) in path {
                    let mut block = RgbaImage::new(w.min(MAX_SIDE), h.min(MAX_SIDE));
                    for (bx, by, p) in block.enumerate_pixels_mut() {
                        *p = *tile.get_pixel(bx % tile.width(), by % tile.height());
                    }
                    draw(&mut self.layer(id).img, &block, x, y, mask, 255);
                }
            }
            "cstroke" | "lstroke" => {
                // Strokes are not drawn, but they use up the path.
                let id = int(a.get(1));
                self.layer(id).path.clear();
            }
            "move" => {
                // move,layer,parent,x,y,z
                let id = int(a.first());
                if id > 0 {
                    let l = self.layer(id);
                    l.parent = int(a.get(1));
                    l.x = int(a.get(2));
                    l.y = int(a.get(3));
                    l.z = int(a.get(4));
                }
            }
            "shade" => {
                let id = int(a.first());
                self.layer(id).opacity = uint(a.get(1)).min(255) as u8;
            }
            "dispose" => {
                let id = int(a.first());
                if id != 0 {
                    self.layers.remove(&id);
                }
            }
            "sync" => return Reply::Sync(a.first().cloned().unwrap_or_default()),
            "audio" | "video" | "file" | "pipe" => {
                return Reply::RefuseStream(a.first().cloned().unwrap_or_default())
            }
            "error" => {
                return Reply::End(format!(
                    "{} (status {})",
                    a.first().map(String::as_str).unwrap_or("error"),
                    a.get(1).map(String::as_str).unwrap_or("?")
                ))
            }
            "disconnect" => return Reply::End("the remote side disconnected".into()),
            "required" => {
                return Reply::End(format!(
                    "the connection needs {} that the entry does not have",
                    a.join(", ")
                ))
            }
            _ => {}
        }
        Reply::None
    }

    fn draw_stream(&mut self, s: ImageStream) {
        let Ok(img) = image::load_from_memory(&s.data) else {
            tracing::debug!(layer = s.layer, "renderer: undecodable image");
            return;
        };
        let img = img.to_rgba8();
        self.fit(s.layer, s.x, s.y, img.width(), img.height());
        draw(&mut self.layer(s.layer).img, &img, s.x, s.y, s.mask, 255);
    }

    #[allow(clippy::too_many_arguments)]
    fn copy(
        &mut self,
        src: i32,
        sx: i32,
        sy: i32,
        w: u32,
        h: u32,
        mask: u32,
        dst: i32,
        dx: i32,
        dy: i32,
    ) {
        let Some(from) = self.layers.get(&src) else {
            return;
        };
        let (fw, fh) = from.img.dimensions();
        // Clip the source rectangle to the source layer.
        let (x0, y0) = (sx.max(0), sy.max(0));
        let x1 = (sx as i64 + w as i64).min(fw as i64);
        let y1 = (sy as i64 + h as i64).min(fh as i64);
        if x1 <= x0 as i64 || y1 <= y0 as i64 {
            return;
        }
        // A copy within one layer (scrolling) may overlap: take it out first.
        let part = imageops::crop_imm(
            &from.img,
            x0 as u32,
            y0 as u32,
            (x1 - x0 as i64) as u32,
            (y1 - y0 as i64) as u32,
        )
        .to_image();
        let (dx, dy) = (dx + (x0 - sx), dy + (y0 - sy));
        self.fit(dst, dx, dy, part.width(), part.height());
        draw(&mut self.layer(dst).img, &part, dx, dy, mask, 255);
    }

    /// Layer `id` with its visible children drawn on it.
    fn composed(&self, id: i32, depth: usize) -> Option<RgbaImage> {
        let mut img = self.layers.get(&id)?.img.clone();
        if depth >= MAX_DEPTH {
            return Some(img);
        }
        let mut children: Vec<(&i32, &Layer)> = self
            .layers
            .iter()
            .filter(|(cid, l)| **cid > 0 && **cid != id && l.parent == id)
            .collect();
        children.sort_by_key(|(cid, l)| (l.z, **cid));
        for (cid, l) in children {
            if l.opacity == 0 {
                continue;
            }
            if let Some(child) = self.composed(*cid, depth + 1) {
                draw(&mut img, &child, l.x, l.y, 0xE, l.opacity);
            }
        }
        Some(img)
    }

    /// The screen as a user would see it (without the mouse pointer).
    pub fn screen(&self) -> RgbaImage {
        let mut img = self.composed(0, 0).unwrap_or_default();
        // The screen is opaque: whatever was never drawn shows as black.
        for p in img.pixels_mut() {
            let mut black = Rgba([0, 0, 0, 255]);
            blend(&mut black, *p, 0xE, 255);
            *p = black;
        }
        img
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn png(w: u32, h: u32, color: [u8; 4]) -> String {
        let img = RgbaImage::from_pixel(w, h, Rgba(color));
        let mut out = std::io::Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Png).unwrap();
        base64::engine::general_purpose::STANDARD.encode(out.into_inner())
    }

    #[test]
    fn images_rects_and_copies_draw_on_the_screen() {
        let mut d = Display::new();
        d.apply("size", &s(&["0", "100", "50"]));
        assert_eq!(d.size(), (100, 50));
        // A red 10x10 image at (5, 5), sent in two blobs, each its own
        // base64.
        let data = png(10, 10, [255, 0, 0, 255]);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&data)
            .unwrap();
        let (p1, p2) = bytes.split_at(bytes.len() / 2);
        let e = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        d.apply("img", &s(&["1", "14", "0", "image/png", "5", "5"]));
        d.apply("blob", &s(&["1", &e(p1)]));
        d.apply("blob", &s(&["1", &e(p2)]));
        d.apply("end", &s(&["1"]));
        // A green rect filled at (50, 10).
        d.apply("rect", &s(&["0", "50", "10", "4", "4"]));
        d.apply("cfill", &s(&["14", "0", "0", "255", "0", "255"]));
        // Copy the red square to (80, 30).
        d.apply(
            "copy",
            &s(&["0", "5", "5", "10", "10", "12", "0", "80", "30"]),
        );
        let img = d.screen();
        assert_eq!(*img.get_pixel(6, 6), Rgba([255, 0, 0, 255]));
        assert_eq!(*img.get_pixel(51, 11), Rgba([0, 255, 0, 255]));
        assert_eq!(*img.get_pixel(85, 35), Rgba([255, 0, 0, 255]));
        assert_eq!(*img.get_pixel(0, 0), Rgba([0, 0, 0, 255]));
        assert_eq!(d.apply("sync", &s(&["1234"])), Reply::Sync("1234".into()));
    }

    #[test]
    fn buffers_layers_and_streams() {
        let mut d = Display::new();
        d.apply("size", &s(&["0", "40", "40"]));
        // An off-screen buffer grows to fit, and is copied in.
        d.apply("rect", &s(&["-1", "0", "0", "8", "8"]));
        d.apply("cfill", &s(&["12", "-1", "0", "0", "255", "255"]));
        d.apply("copy", &s(&["-1", "0", "0", "8", "8", "12", "0", "0", "0"]));
        // A visible layer at (20, 20), half transparent white.
        d.apply("size", &s(&["1", "10", "10"]));
        d.apply("rect", &s(&["1", "0", "0", "10", "10"]));
        d.apply("cfill", &s(&["12", "1", "255", "255", "255", "255"]));
        d.apply("move", &s(&["1", "0", "20", "20", "1"]));
        d.apply("shade", &s(&["1", "128"]));
        let img = d.screen();
        assert_eq!(*img.get_pixel(3, 3), Rgba([0, 0, 255, 255]));
        let p = img.get_pixel(25, 25);
        assert!(p[0] > 100 && p[0] < 160, "{:?}", p);
        // Disposing hides it.
        d.apply("dispose", &s(&["1"]));
        assert_eq!(*d.screen().get_pixel(25, 25), Rgba([0, 0, 0, 255]));
        // Streams the renderer does not take are refused; errors end it.
        assert_eq!(
            d.apply("audio", &s(&["4", "audio/L16"])),
            Reply::RefuseStream("4".into())
        );
        assert_eq!(
            d.apply("img", &s(&["5", "14", "0", "text/plain", "0", "0"])),
            Reply::RefuseStream("5".into())
        );
        assert!(matches!(
            d.apply("error", &s(&["Aborted", "519"])),
            Reply::End(_)
        ));
    }

    #[test]
    fn a_scroll_copy_within_one_layer_overlaps_correctly() {
        let mut d = Display::new();
        d.apply("size", &s(&["0", "4", "4"]));
        for (y, c) in [(0, "10"), (1, "20"), (2, "30"), (3, "40")] {
            d.apply("rect", &s(&["0", "0", &y.to_string(), "4", "1"]));
            d.apply("cfill", &s(&["12", "0", c, "0", "0", "255"]));
        }
        // Scroll up one row.
        d.apply("copy", &s(&["0", "0", "1", "4", "3", "12", "0", "0", "0"]));
        let img = d.screen();
        assert_eq!(
            (0..4).map(|y| img.get_pixel(0, y)[0]).collect::<Vec<_>>(),
            vec![20, 30, 40, 40]
        );
    }
}
