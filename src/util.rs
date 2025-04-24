use anyhow::{Result, bail};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
};

pub const SEGMENT_BITS: i32 = 0x7F;
pub const CONTINUE_BIT: i32 = 0x80;

#[inline]
pub async fn read_var_int_with_len<R: AsyncRead + Unpin>(mut reader: R) -> Result<(i32, usize)> {
    let mut value = 0i32;
    let mut position = 0i32;
    let mut current_byte;
    let mut read_bytes = 0;

    loop {
        current_byte = reader.read_i8().await? as i32;
        value |= (current_byte & SEGMENT_BITS) << position;
        read_bytes += 1;

        if current_byte & CONTINUE_BIT == 0 {
            break;
        }

        position += 7;
        if position >= 32 {
            bail!("varint too big");
        }
    }

    Ok((value, read_bytes))
}

#[inline]
pub async fn read_var_int<R: AsyncRead + Unpin>(reader: R) -> Result<i32> {
    read_var_int_with_len(reader)
        .await
        .map(|(varint, _)| varint)
}

#[inline]
pub async fn write_var_int<W: AsyncWrite + Unpin>(mut writer: W, mut n: i32) -> Result<()> {
    loop {
        if n & !SEGMENT_BITS == 0 {
            writer.write_i8(n as i8).await?;
            break;
        }

        writer
            .write_i8(((n & SEGMENT_BITS) | CONTINUE_BIT) as i8)
            .await?;
        n = (n.cast_unsigned() >> 7).cast_signed()
    }

    Ok(())
}

#[inline]
pub fn split_stream_into_buffered(
    stream: TcpStream,
) -> (BufReader<OwnedReadHalf>, BufWriter<OwnedWriteHalf>) {
    let (reader, writer) = stream.into_split();

    (BufReader::new(reader), BufWriter::new(writer))
}
