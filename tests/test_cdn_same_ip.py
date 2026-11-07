import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('cdn_same_ip', Path(__file__).resolve().parents[1] / 'lib/cdn_same_ip.py')
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)
SOURCE = '''class DomainAdmin:
    def _validate_domain_ips(self, model, server_ips):
        if not model.resolves:
            raise ValueError('DNS')
        domain_ip_matches_server = model.matches
        if not domain_ip_matches_server and model.mode == DomainType.direct:
            raise ValueError('Direct')
        OLD
            raise ValueError('CDN')
        return True
'''.replace('OLD', patch.OLD)

class PatchTests(unittest.TestCase):
    def test_scope(self):
        from types import SimpleNamespace
        modes = SimpleNamespace(cdn='cdn', auto_cdn_ip='auto', relay='relay', fake='fake', direct='direct')
        env = {'DomainType': modes}
        exec(patch.transform(SOURCE), env)
        validate = env['DomainAdmin']()._validate_domain_ips
        for mode in [modes.cdn, modes.auto_cdn_ip]:
            self.assertTrue(validate(SimpleNamespace(mode=mode, resolves=True, matches=True), []))
            with self.assertRaisesRegex(ValueError, 'DNS'):
                validate(SimpleNamespace(mode=mode, resolves=False, matches=True), [])
        with self.assertRaisesRegex(ValueError, 'Direct'):
            validate(SimpleNamespace(mode=modes.direct, resolves=True, matches=False), [])
        with self.assertRaisesRegex(ValueError, 'CDN'):
            validate(SimpleNamespace(mode=modes.relay, resolves=True, matches=True), [])

    def test_idempotent_reversible_preserves_other_patches(self):
        source = '# other module\n' + SOURCE
        edited = patch.transform(source)
        self.assertEqual(edited, patch.transform(edited))
        self.assertEqual(source, patch.transform(edited, True))
        self.assertEqual(source, patch.transform(source, True))

    def test_unknown_and_duplicate_fail_closed(self):
        for source in [SOURCE.replace(patch.OLD, 'if False:'), SOURCE + SOURCE]:
            with self.assertRaises(ValueError):
                patch.transform(source)

if __name__ == '__main__':
    unittest.main()
