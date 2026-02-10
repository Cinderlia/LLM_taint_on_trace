import unittest

from llm_utils.session_validator import validate_and_fix_php_session_text


class TestSessionValidator(unittest.TestCase):
    def test_valid_simple(self):
        r = validate_and_fix_php_session_text("errors|b:1;")
        self.assertTrue(r.ok)
        self.assertEqual(r.fixed_text, "errors|b:1;")
        self.assertFalse(r.changed)

    def test_fix_string_length_ascii(self):
        r = validate_and_fix_php_session_text('k|s:3:"test";')
        self.assertTrue(r.ok)
        self.assertEqual(r.fixed_text, 'k|s:4:"test";')
        self.assertTrue(r.changed)

    def test_fix_string_length_utf8_bytes(self):
        r = validate_and_fix_php_session_text('u|s:1:"中";')
        self.assertTrue(r.ok)
        self.assertEqual(r.fixed_text, 'u|s:3:"中";')
        self.assertTrue(r.changed)

    def test_invalid_missing_semicolon(self):
        r = validate_and_fix_php_session_text('k|s:4:"test"')
        self.assertFalse(r.ok)

    def test_array_with_string_fix(self):
        r = validate_and_fix_php_session_text('a|a:1:{s:3:"key";s:1:"中";}')
        self.assertTrue(r.ok)
        self.assertEqual(r.fixed_text, 'a|a:1:{s:3:"key";s:3:"中";}')
        self.assertTrue(r.changed)


if __name__ == "__main__":
    unittest.main()

