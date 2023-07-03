use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;

use crate::error::Result;
use crate::error::WdaError;

#[cfg(feature = "extra_auto")]
pub fn png_v_concat<I, P, S>(one: u32, whole: u32, images: &[I]) -> image::ImageBuffer<P, Vec<S>>
where
    I: image::GenericImageView<Pixel = P> + 'static,
    P: image::Pixel<Subpixel = S> + 'static,
    S: image::Primitive + 'static,
{
    use image::GenericImage;

    let cnt_img = images.len();
    let one_h = images[0].height();
    let one_w = images[0].width();
    let incompl_last_h = whole % one;

    dbgg!(&cnt_img, &one_h, &one_w, &incompl_last_h);

    if cnt_img == 1 {
        let mut imgbuf = image::ImageBuffer::new(one_w, one_h);
        imgbuf.copy_from(&images[0], 0, 0).unwrap();
        return imgbuf;
    }

    // final output width and height
    let img_w_out = one_w;
    let img_h_out = one_h * ((images.len() - 1) as u32) + incompl_last_h;

    let mut imgbuf = image::ImageBuffer::new(img_w_out, img_h_out);
    let mut curr_y_out = 0; // the active cursor at y, in final output image

    // copy one by one
    for img in &images[0..cnt_img - 1] {
        imgbuf.copy_from(img, 0, curr_y_out).unwrap();
        curr_y_out += img.height();
    }

    // the last one is special
    if incompl_last_h > 0 {
        let cropped: image::SubImage<&I> =
            images[cnt_img - 1].view(0, one_h - incompl_last_h, img_w_out, incompl_last_h);
        imgbuf
            .copy_from(&cropped.to_image(), 0, curr_y_out)
            .unwrap();
    }

    imgbuf
}

pub fn decode_b64_file(from_file: &str, to_file: &str) -> Result<()> {
    use base64::Engine;

    let mut buf_b64 = [0u8; 4096];
    let mut buf_de = [0u8; 4096]; // must >= 3072

    let mut f_b64;

    match OpenOptions::new().read(true).open(from_file) {
        Ok(f) => f_b64 = f,
        Err(_e) => {
            dbgg!(_e, from_file);
            return Err(WdaError::Buggy);
        }
    }

    let mut f_de = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(to_file)
        .expect("open file");

    loop {
        let nread = f_b64.read(&mut buf_b64).expect("read io");
        if nread == 0 {
            break;
        }

        // dbgg!(nread);
        if let Err(e) =
            base64::engine::general_purpose::STANDARD.decode_slice(&buf_b64[0..nread], &mut buf_de)
        {
            match e {
                base64::DecodeSliceError::DecodeError(_) => {
                    dbgg!(from_file);
                    return Err(WdaError::Base64DataCorrupt(e));
                }
                _ => {
                    dbgg!(e);
                    return Err(WdaError::Buggy);
                }
            }
        }

        f_de.write_all(&buf_de[0..((nread * 6) / 8)])
            .expect("io write");
    }

    Ok(())
}
