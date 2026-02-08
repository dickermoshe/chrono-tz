/// This test is compiled by the Github workflows with the
/// range filter set thusly:
/// CHRONO_TZ_TIME_RANGE="1577836800..1577923200" (2020-01-01 UTC only).
///
/// We use it as an end-to-end sanity check that range filtering is
/// actually applied in generated timezone data.

#[cfg(test)]
mod tests {
    use chrono::{Offset, TimeZone};
    use chrono_tz::America::New_York;

    fn offset_seconds(year: i32, month: u32, day: u32) -> i32 {
        let dt = New_York
            .with_ymd_and_hms(year, month, day, 12, 0, 0)
            .single()
            .unwrap();
        dt.offset().fix().local_minus_utc()
    }

    #[test]
    fn range_filtering_is_applied_end_to_end() {
        // In this narrow winter-only range, New York should stay on EST (-5h).
        assert_eq!(offset_seconds(2020, 1, 1), -5 * 3600);

        // These dates are normally EDT (-4h), but should be pinned to EST after trimming.
        assert_eq!(offset_seconds(2020, 7, 1), -5 * 3600);
        assert_eq!(offset_seconds(2010, 7, 1), -5 * 3600);
        assert_eq!(offset_seconds(2030, 7, 1), -5 * 3600);
    }
}
