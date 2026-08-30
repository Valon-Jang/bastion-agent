import unittest

from tolerance_app import DEFAULT_PARTS, Dimension, calculate_stack


class PublicToleranceTests(unittest.TestCase):
    def test_nominal_clearance_is_calculated(self) -> None:
        result = calculate_stack(list(DEFAULT_PARTS), 0.5, 1.5)
        self.assertEqual(result.nominal, 1.0)

    def test_dimension_limits(self) -> None:
        dimension = Dimension("A", 10.0, 0.2)
        self.assertEqual(dimension.minimum, 9.8)
        self.assertEqual(dimension.maximum, 10.2)


if __name__ == "__main__":
    unittest.main()
