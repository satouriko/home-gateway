import datetime as dt
import unittest
from pricing import pricing_state, routine_allowed

class PricingTests(unittest.TestCase):
    def stamp(self, text):
        return dt.datetime.fromisoformat(text).timestamp()

    def test_beijing_weekday_peak_boundaries_independent_of_host_timezone(self):
        for hour, expected in [('08:59', False), ('09:00', True), ('11:59', True), ('12:00', False), ('13:59', False), ('14:00', True), ('17:59', True), ('18:00', False)]:
            with self.subTest(hour=hour):
                self.assertEqual(pricing_state(self.stamp('2026-11-02T'+hour+':00+08:00'))['peak'], expected)

    def test_weekends_and_verified_public_holidays_are_off_peak(self):
        self.assertFalse(pricing_state(self.stamp('2026-11-01T10:00:00+08:00'))['peak'])
        self.assertFalse(pricing_state(self.stamp('2026-11-02T10:00:00+08:00'), {'public_holidays':['2026-11-02']})['peak'])

    def test_routine_job_has_time_to_finish_before_peak(self):
        self.assertTrue(routine_allowed(self.stamp('2026-11-02T12:30:00+08:00')))
        self.assertFalse(routine_allowed(self.stamp('2026-11-02T13:55:00+08:00')))
        self.assertFalse(routine_allowed(self.stamp('2026-11-02T10:00:00+08:00')))

if __name__ == '__main__': unittest.main()
