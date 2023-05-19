//! Encoder.

use crate::{fountain, ur::UR};
use core::str;

/// An encoder.
#[cfg(feature = "alloc")]
pub type Encoder<'a, 'b> = BaseEncoder<'a, 'b, fountain::encoder::Alloc>;

#[cfg(feature = "alloc")]
impl<'a, 'b> Encoder<'a, 'b> {
    /// Construct a new [`Encoder`].
    pub const fn new() -> Self {
        Self {
            fountain: fountain::encoder::Encoder::new(),
            ur_type: None,
        }
    }
}

/// An static encoder.
///
/// Does not allocate memory.
pub type HeaplessEncoder<'a, 'b, const MAX_FRAGMENT_LEN: usize, const MAX_SEQUENCE_COUNT: usize> =
    BaseEncoder<'a, 'b, fountain::encoder::Heapless<MAX_FRAGMENT_LEN, MAX_SEQUENCE_COUNT>>;

impl<'a, 'b, const MAX_FRAGMENT_LEN: usize, const MAX_SEQUENCE_COUNT: usize>
    HeaplessEncoder<'a, 'b, MAX_FRAGMENT_LEN, MAX_SEQUENCE_COUNT>
{
    /// Construct a new [`HeaplessEncoder`].
    pub const fn new_heapless() -> Self {
        Self {
            fountain: fountain::encoder::HeaplessEncoder::new_heapless(),
            ur_type: None,
        }
    }
}

/// A uniform resource encoder with an underlying fountain encoding.
///
/// # Examples
///
/// See the [`crate`] documentation for an example.
pub struct BaseEncoder<'a, 'b, T: fountain::encoder::Types> {
    ur_type: Option<&'a str>,
    fountain: fountain::encoder::BaseEncoder<'b, T>,
}

impl<'a, 'b, T: fountain::encoder::Types> BaseEncoder<'a, 'b, T> {
    /// Creates a new encoder for the given message payload.
    ///
    /// The emitted fountain parts will respect the maximum fragment length
    /// argument.
    ///
    /// # Examples
    ///
    /// See the [`crate`] documentation for an example.
    ///
    /// # Panics
    ///
    /// This function panics if `ur_type` or `message` is empty, or if
    /// `max_fragment_length` is zero.
    pub fn start(&mut self, ur_type: &'a str, message: &'b [u8], max_fragment_length: usize) {
        self.ur_type = Some(ur_type);
        self.fountain.start(message, max_fragment_length);
    }

    /// Returns the current count of already emitted parts.
    ///
    /// # Examples
    ///
    /// ```
    /// use ur::Encoder;
    ///
    /// let mut encoder = Encoder::new();
    /// encoder.start("bytes", "data".as_bytes(), 5);
    ///
    /// assert_eq!(encoder.current_sequence(), 0);
    /// encoder.next_part();
    /// assert_eq!(encoder.current_sequence(), 1);
    /// ```
    #[inline]
    pub fn current_sequence(&self) -> u32 {
        self.fountain.current_sequence()
    }

    /// Returns the number of segments the original message has been split up into.
    ///
    /// # Examples
    ///
    /// ```
    /// use ur::Encoder;
    ///
    /// let mut encoder = Encoder::new();
    /// encoder.start("bytes", "data".as_bytes(), 3);
    /// assert_eq!(encoder.sequence_count(), 2);
    /// ```
    #[inline]
    pub fn sequence_count(&self) -> u32 {
        self.fountain.sequence_count()
    }

    /// Returns the URI corresponding to next fountain part.
    ///
    /// # Examples
    ///
    /// See the [`crate`] documentation for an example.
    pub fn next_part(&mut self) -> UR {
        UR::MultiPartDeserialized {
            ur_type: self.ur_type.expect("encoder is not initialized"),
            fragment: self.fountain.next_part(),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::ur::tests::make_message_ur;

    #[test]
    fn test_ur_encoder() {
        const TEST_VECTORS: &[&str] = &[
            "ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh",
            "ur:bytes/2-9/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz",
            "ur:bytes/3-9/lpaxascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjksopdzmol",
            "ur:bytes/4-9/lpaaascfadaxcywenbpljkhdcasotkhemthydawydtaxneurlkosgwcekonertkbrlwmplssjtammdplolsbrdzcrtas",
            "ur:bytes/5-9/lpahascfadaxcywenbpljkhdcatbbdfmssrkzmcwnezelennjpfzbgmuktrhtejscktelgfpdlrkfyfwdajldejokbwf",
            "ur:bytes/6-9/lpamascfadaxcywenbpljkhdcackjlhkhybssklbwefectpfnbbectrljectpavyrolkzczcpkmwidmwoxkilghdsowp",
            "ur:bytes/7-9/lpatascfadaxcywenbpljkhdcavszmwnjkwtclrtvaynhpahrtoxmwvwatmedibkaegdosftvandiodagdhthtrlnnhy",
            "ur:bytes/8-9/lpayascfadaxcywenbpljkhdcadmsponkkbbhgsoltjntegepmttmoonftnbuoiyrehfrtsabzsttorodklubbuyaetk",
            "ur:bytes/9-9/lpasascfadaxcywenbpljkhdcajskecpmdckihdyhphfotjojtfmlnwmadspaxrkytbztpbauotbgtgtaeaevtgavtny",
            "ur:bytes/10-9/lpbkascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtwdkiplzs",
            "ur:bytes/11-9/lpbdascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjkvetiiapk",
            "ur:bytes/12-9/lpbnascfadaxcywenbpljkhdcarllaluzmdmgstospeyiefmwejlwtpedamktksrvlcygmzemovovllarodtmtbnptrs",
            "ur:bytes/13-9/lpbtascfadaxcywenbpljkhdcamtkgtpknghchchyketwsvwgwfdhpgmgtylctotzopdrpayoschcmhplffziachrfgd",
            "ur:bytes/14-9/lpbaascfadaxcywenbpljkhdcapazewnvonnvdnsbyleynwtnsjkjndeoldydkbkdslgjkbbkortbelomueekgvstegt",
            "ur:bytes/15-9/lpbsascfadaxcywenbpljkhdcaynmhpddpzmversbdqdfyrehnqzlugmjzmnmtwmrouohtstgsbsahpawkditkckynwt",
            "ur:bytes/16-9/lpbeascfadaxcywenbpljkhdcawygekobamwtlihsnpalnsghenskkiynthdzotsimtojetprsttmukirlrsbtamjtpd",
            "ur:bytes/17-9/lpbyascfadaxcywenbpljkhdcamklgftaxykpewyrtqzhydntpnytyisincxmhtbceaykolduortotiaiaiafhiaoyce",
            "ur:bytes/18-9/lpbgascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtntwkbkwy",
            "ur:bytes/19-9/lpbwascfadaxcywenbpljkhdcadekicpaajootjzpsdrbalpeywllbdsnbinaerkurspbncxgslgftvtsrjtksplcpeo",
            "ur:bytes/20-9/lpbbascfadaxcywenbpljkhdcayapmrleeleaxpasfrtrdkncffwjyjzgyetdmlewtkpktgllepfrltataztksmhkbot",
        ];

        let ur = make_message_ur(256, "Wolf");

        fn test<'a, T: fountain::encoder::Types>(
            encoder: &mut BaseEncoder<'static, 'a, T>,
            ur: &'a [u8],
        ) {
            encoder.start("bytes", &ur, 30);
            assert_eq!(encoder.sequence_count(), 9);
            for (index, &part) in TEST_VECTORS.iter().enumerate() {
                assert_eq!(encoder.current_sequence(), index.try_into().unwrap());
                assert_eq!(encoder.next_part().to_string(), part);
            }
        }

        let mut heapless_encoder: HeaplessEncoder<'_, '_, 30, 16> = HeaplessEncoder::new_heapless();
        let mut encoder = Encoder::new();

        test(&mut heapless_encoder, &ur);
        test(&mut encoder, &ur);
    }
}
