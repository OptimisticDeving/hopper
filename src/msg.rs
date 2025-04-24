use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::util::{read_var_int, write_var_int};

#[derive(Debug)]
pub enum Message {
    AddNonce(u32),
    RemoveNonce(u32),
    Message { nonce: u32, data: Vec<u8> },
}

impl Message {
    #[inline]
    pub async fn read<R: AsyncRead + Unpin>(mut reader: R) -> Result<Self> {
        Ok(match reader.read_u8().await? {
            0 => Self::AddNonce(reader.read_u32().await?),
            1 => Self::RemoveNonce(reader.read_u32().await?),
            2 => Self::Message {
                nonce: reader.read_u32().await?,
                data: {
                    let length = read_var_int(&mut reader).await?;
                    let mut buffer = vec![0u8; length.try_into()?];
                    reader.read_exact(&mut buffer).await?;
                    buffer
                },
            },
            id => bail!("unrecognized packet id {id}"),
        })
    }

    #[inline]
    pub async fn write<W: AsyncWrite + Unpin>(&self, mut writer: W) -> Result<()> {
        match self {
            Self::AddNonce(nonce) => {
                writer.write_u8(0).await?;
                writer.write_u32(*nonce).await?;
            }
            Self::RemoveNonce(nonce) => {
                writer.write_u8(1).await?;
                writer.write_u32(*nonce).await?;
            }
            Self::Message { nonce, data } => {
                writer.write_u8(2).await?;
                writer.write_u32(*nonce).await?;
                write_var_int(&mut writer, data.len().try_into()?).await?;
                writer.write_all(&data).await?;
            }
        }

        Ok(())
    }
}
