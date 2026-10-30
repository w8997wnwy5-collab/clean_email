import unittest
from datetime import date, datetime, timedelta, timezone

from clean_email import imap_utf7
from clean_email.imap import (
    MailError, fetch_records, imap_date, message_from_fetch, parse_internaldate, parse_list_response,
    quote, quote_mailbox, uid_set, validate_folder_name,
)


class ModifiedUtf7Test(unittest.TestCase):
    def test_known_values(self):
        cases = {
            "INBOX": "INBOX",
            "Società & Co": "Societ&AOA- &- Co",
            "Entwürfe": "Entw&APw-rfe",
            "日本語": "&ZeVnLIqe-",
            "Posta 📬": "Posta &2D3c7A-",
        }
        for plain, encoded in cases.items():
            self.assertEqual(imap_utf7.encode(plain), encoded)
            self.assertEqual(imap_utf7.decode(encoded), plain)

    def test_invalid_input_is_kept(self):
        self.assertEqual(imap_utf7.decode("&ZeVn"), "&ZeVn")
        self.assertEqual(imap_utf7.decode("&!!!-"), "&!!!-")


class HelpersTest(unittest.TestCase):
    def test_uid_set(self):
        self.assertEqual(uid_set([5, 1, 2, 3, 9, 10, 7]), "1:3,5,7,9:10")
        self.assertEqual(uid_set([]), "")

    def test_dates_are_english_whatever_the_locale(self):
        self.assertEqual(imap_date(date(2026, 8, 3)), "3-Aug-2026")

    def test_internaldate(self):
        parsed = parse_internaldate(" 7-Jul-2026 02:44:25 -0700")
        self.assertEqual(parsed, datetime(2026, 7, 7, 2, 44, 25, tzinfo=timezone(-timedelta(hours=7))))
        self.assertIsNone(parse_internaldate("ieri"))

    def test_quoting(self):
        self.assertEqual(quote_mailbox("Sent Messages"), '"Sent Messages"')
        self.assertEqual(quote('a"b\\c'), '"a\\"b\\\\c"')
        with self.assertRaises(MailError):
            quote("x\r\nA1 DELETE INBOX")

    def test_folder_names(self):
        self.assertEqual(validate_folder_name(" Newsletter "), "Newsletter")
        for bad in ("", "a*b", "a%", "/x", "x/", "a//b", 'a"b', "a\nb"):
            with self.assertRaises(MailError, msg=bad):
                validate_folder_name(bad)


class ListResponseTest(unittest.TestCase):
    def test_quoted_atom_literal_and_nil(self):
        data = [
            b'(\\HasNoChildren \\Trash) "/" "Deleted Messages"',
            b'(\\HasNoChildren) "/" INBOX',
            (b'(\\HasNoChildren) "/" {9}', b'Weird"Box'),
            b'',
            b'(\\Noselect) NIL "Societ&AOA-"',
        ]
        folders = parse_list_response(data)
        self.assertEqual([f.name for f in folders], ["Deleted Messages", "INBOX", 'Weird"Box', "Società"])
        self.assertIn("\\trash", folders[0].flags)
        self.assertIsNone(folders[3].delimiter)
        self.assertFalse(folders[3].selectable)


class FetchResponseTest(unittest.TestCase):
    HEADERS = b"From: Shop <promo@shop.ch>\r\nSubject: =?utf-8?q?Offerta_=E2=82=AC?=\r\n\r\n"

    def test_uid_before_or_after_the_literal(self):
        data = [
            (b'1 (UID 11 FLAGS (\\Seen) INTERNALDATE "01-Jan-2026 10:00:00 +0000" RFC822.SIZE 99 '
             b'BODY[HEADER.FIELDS (FROM SUBJECT)] {%d}' % len(self.HEADERS), self.HEADERS),
            b')',
            (b'2 (BODY[HEADER.FIELDS ("FROM" "SUBJECT")] {%d}' % len(self.HEADERS), self.HEADERS),
            b' UID 12 FLAGS ())',
            b'3 (UID 99 FLAGS (\\Seen))',  # unsolicited flag update, no literal
        ]
        records = list(fetch_records(data))
        self.assertEqual(len(records), 3)
        first = message_from_fetch(*records[0], "INBOX")
        second = message_from_fetch(*records[1], "INBOX")
        self.assertEqual((first.uid, second.uid), (11, 12))
        self.assertTrue(first.seen)
        self.assertFalse(second.seen)
        self.assertEqual(first.subject, "Offerta €")
        self.assertEqual(first.from_addr, "promo@shop.ch")
        self.assertEqual(first.size, 99)
        self.assertEqual(first.date, datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc))


if __name__ == "__main__":
    unittest.main()
