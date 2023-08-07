// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use embedded_io::Write;

use crate::encoder::compact_size::encode_compact_size;
use crate::transaction::{Input, Inputs, Output, OutputPoint, Outputs};

pub fn encode_inputs<I, W>(mut w: W, inputs: &Inputs<I>) -> Result<usize, W::Error>
where
    I: for<'a> nom::Compare<&'a [u8]>
        + Clone
        + PartialEq
        + core::fmt::Debug
        + nom::InputTake
        + nom::InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<core::ops::RangeFrom<usize>>,
    W: Write,
{
    let mut count = 0;

    count += encode_compact_size(&mut w, inputs.len())?;

    for input in inputs.iter() {
        count += encode_input(&mut w, &input)?;
    }

    Ok(count)
}

pub fn encode_input<I, W>(mut w: W, input: &Input<I>) -> Result<usize, W::Error>
where
    I: nom::InputLength + nom::InputIter<Item = u8>,
    W: Write,
{
    let mut count = 0;

    count += encode_output_point(&mut w, &input.previous_output)?;
    count += encode_compact_size(&mut w, u64::try_from(input.script_sig.input_len()).unwrap())?;

    for byte in input.script_sig.iter_elements() {
        count += w.write(&[byte])?;
    }

    count += w.write(&input.sequence.to_le_bytes())?;

    Ok(count)
}

pub fn encode_output_point<W>(mut w: W, output_point: &OutputPoint) -> Result<usize, W::Error>
where
    W: Write,
{
    let mut count = 0;

    count += w.write(output_point.hash.as_ref())?;
    count += w.write(&output_point.index.to_le_bytes())?;

    Ok(count)
}

pub fn encode_outputs<I, W>(mut w: W, outputs: &Outputs<I>) -> Result<usize, W::Error>
where
    I: for<'a> nom::Compare<&'a [u8]>
        + Clone
        + PartialEq
        + core::fmt::Debug
        + nom::InputTake
        + nom::InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<core::ops::RangeFrom<usize>>,
    W: Write,
{
    let mut count = 0;

    count += encode_compact_size(&mut w, outputs.len())?;

    for output in outputs.iter() {
        count += encode_output(&mut w, &output)?;
    }

    Ok(count)
}

pub fn encode_output<W, I>(mut w: W, output: &Output<I>) -> Result<usize, W::Error>
where
    I: nom::InputIter<Item = u8> + nom::InputLength,
    W: Write,
{
    let mut count = 0;

    count += w.write(&output.value.to_le_bytes())?;
    count += encode_compact_size(
        &mut w,
        u64::try_from(output.script_pubkey.input_len()).unwrap(),
    )?;

    for byte in output.script_pubkey.iter_elements() {
        count += w.write(&[byte])?;
    }

    Ok(count)
}
