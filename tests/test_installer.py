from pathlib import Path
import re
import unittest

INSTALLER=Path(__file__).resolve().parents[1]/'install.sh'
source=re.search(r"# >>> release resolver.*?<<'PYRESOLVE'\n(.*?)\nPYRESOLVE",INSTALLER.read_text(),re.S)[1]
env={'__name__':'installer_test'}
exec(compile(source,str(INSTALLER),'exec'),env)

def release(tag,**kw):
    return dict(tag_name=tag,draft=False,prerelease=False,published_at='2026-11-14T00:00:00Z',**kw)

class InstallerTests(unittest.TestCase):
    def test_selects_latest_numeric_v2_stable_only(self):
        records=[release('v1.8.9'),release('v3.0.0'),release('v2.9.0'),release('v2.10.0'),release('v2.10.1-rc1')]
        records+=[dict(release('v2.99.0'),draft=True),dict(release('v2.98.0'),prerelease=True),dict(release('v2.97.0'),published_at=None)]
        self.assertEqual(env['select_release'](records),'v2.10.0')
    def test_walks_release_pages(self):
        pages={1:[release('v1.8.2')]*100,2:[release('v2.0.1')]}
        self.assertEqual(env['latest_release'](pages.__getitem__),'v2.0.1')
    def test_no_v2_release_fails_instead_of_main_fallback(self):
        with self.assertRaisesRegex(ValueError,'No published stable'):
            env['latest_release'](lambda page:[release('v1.8.2')])
    def test_api_failure_fails_without_fallback(self):
        with self.assertRaises(ValueError):env['latest_release'](lambda page:{'message':'API rate limit exceeded'})

if __name__=='__main__':unittest.main()
