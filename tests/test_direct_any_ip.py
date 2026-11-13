import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'lib' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
patch = load('direct_any_ip')
cdn = load('cdn_same_ip')
SOURCE = '''class DomainAdmin:
    def _validate_domain_ips(self, model, server_ips):
        if not model.resolves:
            raise ValueError('DNS')
        domain_ip_matches_server = model.matches
        DIRECT
            raise ValueError('Direct')
        CDN
            raise ValueError('CDN')
        return True
'''.replace('DIRECT', patch.OLD).replace('CDN\n', cdn.OLD + '\n')

class DirectTests(unittest.TestCase):
    def test_behavior_and_composition(self):
        modes = SimpleNamespace(**{v:v for v in ['direct','cdn','auto_cdn_ip','relay','fake']})
        env = {'DomainType':modes}
        exec(patch.transform(SOURCE), env)
        validate = env['DomainAdmin']()._validate_domain_ips
        self.assertTrue(validate(SimpleNamespace(mode='direct', resolves=True, matches=False), []))
        with self.assertRaisesRegex(ValueError,'DNS'):
            validate(SimpleNamespace(mode='direct', resolves=False, matches=False), [])
        with self.assertRaisesRegex(ValueError,'CDN'):
            validate(SimpleNamespace(mode='cdn', resolves=True, matches=True), [])
        both = patch.transform(cdn.transform(SOURCE))
        self.assertEqual(both, cdn.transform(patch.transform(SOURCE)))
        self.assertEqual(cdn.transform(SOURCE), patch.transform(both, True))
        self.assertEqual(patch.transform(SOURCE), cdn.transform(both, True))

    def test_idempotence_and_revert(self):
        changed = patch.transform(SOURCE)
        self.assertEqual(changed, patch.transform(changed))
        self.assertEqual(SOURCE, patch.transform(changed, True))
        self.assertEqual(SOURCE, patch.transform(SOURCE, True))

    def test_ambiguous_refused(self):
        for value in [SOURCE + SOURCE, SOURCE.replace(patch.OLD,'if False:')]:
            with self.assertRaises(ValueError):patch.transform(value)

if __name__ == '__main__':unittest.main()
