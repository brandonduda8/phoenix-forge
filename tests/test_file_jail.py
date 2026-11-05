"""file_* tools are jailed to the workspace root (realpath-checked)."""
import os
import unittest

from tests._sandbox import SandboxTestCase, T


class FileJailTests(SandboxTestCase):
    def setUp(self):
        super().setUp()
        self.secret = os.path.join(self.outside, "secret.txt")
        with open(self.secret, "w") as f:
            f.write("TOP-SECRET")
        with open(os.path.join(self.ws, "inside.txt"), "w") as f:
            f.write("hello inside")

    def escapes(self):
        return [
            "../outside/secret.txt",
            "sub/../../outside/secret.txt",
            self.secret,                       # absolute path outside
            "/etc/hostname",
            "~/" + "definitely-not-in-jail.txt",  # expands to $HOME, not the jail
        ]

    def test_read_inside_works(self):
        self.assertEqual(T.tool_file_read({"path": "inside.txt"}, self.ctx), "hello inside")

    def test_read_outside_refused(self):
        for p in self.escapes():
            with self.subTest(path=p):
                out = T.tool_file_read({"path": p}, self.ctx)
                self.assertEqual(out, "REFUSED: path is outside ~/workspace.")
                self.assertNotIn("TOP-SECRET", out)

    def test_symlink_escape_refused(self):
        os.symlink(self.secret, os.path.join(self.ws, "link.txt"))
        os.symlink(self.outside, os.path.join(self.ws, "linkdir"))
        for p in ("link.txt", "linkdir/secret.txt"):
            with self.subTest(path=p):
                self.assertEqual(T.tool_file_read({"path": p}, self.ctx),
                                 "REFUSED: path is outside ~/workspace.")

    def test_sibling_prefix_dir_refused(self):
        # /x/workspace-evil must not pass a naive startswith('/x/workspace') check.
        evil = self.ws + "-evil"
        os.makedirs(evil)
        with open(os.path.join(evil, "f.txt"), "w") as f:
            f.write("evil")
        self.assertEqual(T.tool_file_read({"path": os.path.join(evil, "f.txt")}, self.ctx),
                         "REFUSED: path is outside ~/workspace.")
        self.assertFalse(T._jail_ok(evil))

    def test_workspace_root_itself_is_inside(self):
        self.assertTrue(T._jail_ok(self.ws))
        self.assertTrue(T._jail_ok(os.path.join(self.ws, "a", "b")))

    def test_empty_path_refused(self):
        self.assertTrue(T.tool_file_read({"path": ""}, self.ctx).startswith("REFUSED"))

    def test_write_inside_works(self):
        out = T.tool_file_write({"path": "notes/a.txt", "content": "abc"}, self.ctx)
        self.assertEqual(out, "OK: wrote 3 bytes to notes/a.txt")
        with open(os.path.join(self.ws, "notes", "a.txt")) as f:
            self.assertEqual(f.read(), "abc")

    def test_write_outside_refused_and_nothing_written(self):
        target = os.path.join(self.outside, "pwned.txt")
        for p in ("../outside/pwned.txt", target):
            with self.subTest(path=p):
                out = T.tool_file_write({"path": p, "content": "x"}, self.ctx)
                self.assertTrue(out.startswith("REFUSED"))
        self.assertFalse(os.path.exists(target))

    def test_write_through_symlink_refused(self):
        os.symlink(self.secret, os.path.join(self.ws, "link.txt"))
        out = T.tool_file_write({"path": "link.txt", "content": "overwritten"}, self.ctx)
        self.assertTrue(out.startswith("REFUSED"))
        with open(self.secret) as f:
            self.assertEqual(f.read(), "TOP-SECRET")

    def test_edit_inside_works(self):
        out = T.tool_file_edit({"path": "inside.txt", "old_text": "hello",
                                "new_text": "bye"}, self.ctx)
        self.assertIn("replaced 1 occurrence", out)
        with open(os.path.join(self.ws, "inside.txt")) as f:
            self.assertEqual(f.read(), "bye inside")

    def test_edit_outside_refused_and_unchanged(self):
        out = T.tool_file_edit({"path": "../outside/secret.txt", "old_text": "TOP",
                                "new_text": "NOT"}, self.ctx)
        self.assertTrue(out.startswith("REFUSED"))
        with open(self.secret) as f:
            self.assertEqual(f.read(), "TOP-SECRET")

    def test_stt_transcribe_is_jailed(self):
        out = T.tool_stt_transcribe({"path": "../outside/secret.txt"}, self.ctx)
        self.assertEqual(out, "REFUSED: path is outside ~/workspace.")


if __name__ == "__main__":
    unittest.main()
