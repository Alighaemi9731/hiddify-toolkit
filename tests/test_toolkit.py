import importlib.util
import ipaddress
import fcntl
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('toolkit',Path(__file__).resolve().parents[1]/'lib/toolkit.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
FIX=Path(__file__).parent/'fixtures'

def fixture(feature):
    return (FIX/('rules.py' if feature in ['cdn-same-ip','direct-any-ip'] else 'net.py' if feature=='reality-alpn' else 'domains_api.py')).read_text()

class PatchTests(unittest.TestCase):
    def test_all_idempotent_and_exact_inverse(self):
        for feature in t.PATCHES:
            original=fixture(feature)
            changed=t.transform(feature,original)
            self.assertNotEqual(original,changed)
            self.assertEqual(changed,t.transform(feature,changed))
            self.assertEqual(original,t.transform(feature,changed,True))
            self.assertEqual(original,t.transform(feature,original,True))

    def test_domain_rules_preserve_dns_and_other_modes(self):
        class RuleError(ValueError):pass
        modes=NS(direct='direct',cdn='cdn',relay='relay')
        fake=NS(fake='fake',reality='reality',dns='dns',valid='valid')
        network=NS(get_domain_ips=lambda domain:[ipaddress.ip_address('131.123.41.185')])
        env={'DomainType':modes,'FakeMode':fake,'DomainRuleError':RuleError,'hutils':NS(network=network),'_':lambda msg,**kw:msg}
        original=fixture('direct-any-ip')
        changed=t.transform('direct-any-ip',t.transform('cdn-same-ip',original))
        exec(changed,env)
        check=env['_check_domain_ips'];server=[ipaddress.ip_address('46.62.164.112')]
        self.assertIsNone(check(NS(domain='example.com.',mode='direct',fake_mode='valid'),server))
        network.get_domain_ips=lambda _:server
        self.assertIsNone(check(NS(domain='example.com.',mode='cdn',fake_mode='valid'),server))
        network.get_domain_ips=lambda _:[]
        with self.assertRaisesRegex(RuleError,'cannot be resolved'):check(NS(domain='bad.invalid',mode='direct',fake_mode='valid'),server)
        self.assertEqual(t.transform('cdn-same-ip',original),t.transform('direct-any-ip',changed,True))
        self.assertEqual(t.transform('direct-any-ip',original),t.transform('cdn-same-ip',changed,True))

    def test_host_validation_keeps_ipv4_ipv6_and_rejects_double_dot(self):
        env={};exec(t.transform('fakedomain-dot',fixture('fakedomain-dot')),env)
        for value in ['fast.com.','*.example.com.','fast.com','46.62.164.112','2001:db8::1']:
            self.assertTrue(env['is_host'](value),value)
        for value in ['fast.com..','example.com./bad','bad','bad;command','']:
            self.assertFalse(env['is_host'](value),value)

    def test_unknown_duplicate_or_moved_definitions_rejected(self):
        for feature in t.PATCHES:
            original=fixture(feature)
            for source in [original+original,original.replace(t.PATCHES[feature][2],'# upstream changed condition')]:
                with self.assertRaises((ValueError,SyntaxError)):t.transform(feature,source)

    def test_other_edits_survive_inverse(self):
        feature='direct-any-ip';original=fixture(feature)
        changed=t.transform(feature,original)+'\n# another administrator edit\n'
        self.assertEqual(original+'\n# another administrator edit\n',t.transform(feature,changed,True))

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name)
        self.state=self.base/'state';self.pkg=self.base/'package';self.pkg.mkdir()
        for feature,(rel,*_) in t.PATCHES.items():
            path=self.pkg/rel;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(fixture(feature))
        self.patches=[patch.object(t,'STATE',self.state),patch.object(t,'supported',return_value=(self.pkg,Path(sys.executable))),patch.object(t,'panel_active',return_value=True),patch.object(t,'restart_panel'),patch.object(t,'units'),patch.object(t,'network_sync'),patch.object(t,'installation_busy',return_value=False)]
        self.patches += [patch.object(t.performance,'eligible_defaults',return_value=(list(t.performance.FEATURES),{})),patch.object(t.performance,'preflight'),patch.object(t.performance,'sync')]
        self.mocks=[p.start() for p in self.patches]
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()
    def test_builtin_first_install_and_reinstall_and_explicit_revert(self):
        t.bootstrap();self.assertEqual(set(t.read_config()['enabled']),set(t.DEFAULTS))
        self.assertEqual(self.mocks[3].call_count,1)
        t.bootstrap();self.assertEqual(self.mocks[3].call_count,1)
        t.revert('cdn-same-ip');t.bootstrap()
        self.assertNotIn('cdn-same-ip',t.read_config()['enabled'])
        source=(self.pkg/t.PATCHES['direct-any-ip'][0]).read_text()
        self.assertIn(t.PATCHES['direct-any-ip'][3],source)
        self.assertIn(t.PATCHES['cdn-same-ip'][2],source)
    def test_batch_bad_source_does_not_modify_any_file(self):
        bad=self.pkg/t.PATCHES['direct-any-ip'][0];bad.write_text(bad.read_text().replace(t.PATCHES['direct-any-ip'][2],'if True:'))
        before={p:p.read_bytes() for p in self.pkg.rglob('*.py')}
        with self.assertRaises(ValueError):t.bootstrap()
        self.assertTrue(all(p.read_bytes()==v for p,v in before.items()))
        self.mocks[3].assert_not_called()
    def test_repair_after_source_replacement_and_prepare_no_restart(self):
        t.bootstrap();self.mocks[3].reset_mock()
        file=self.pkg/t.PATCHES['fakedomain-dot'][0];file.write_text(fixture('fakedomain-dot'))
        t.reassert(prepare=True)
        self.assertIn(t.PATCHES['fakedomain-dot'][3],file.read_text())
        self.mocks[3].assert_not_called()
    def test_guard_releases_alias_when_panel_claims_its_port(self):
        t.bootstrap();self.mocks[3].reset_mock()
        receipt=self.state/'port-alias-receipt.json';receipt.write_text('{}')
        self.mocks[5].side_effect=t.AliasConflict('port claimed by panel')
        with patch.object(t,'table_text',return_value='table exists'),patch.object(t,'run') as command:
            with self.assertRaisesRegex(t.AliasConflict,'port claimed'):t.reassert()
            command.assert_called_once_with(['nft','delete','table','inet','hiddify_toolkit_ports'])
        self.assertFalse(receipt.exists())
        self.mocks[3].assert_not_called()

    def test_network_failure_rolls_back_panel_and_settings(self):
        self.mocks[5].side_effect=[RuntimeError('nft failure'),None]
        with self.assertRaisesRegex(RuntimeError,'nft failure'):t.bootstrap()
        self.assertEqual(t.read_config()['enabled'],[])
        for feature,(rel,*_) in t.PATCHES.items():self.assertNotIn(t.PATCHES[feature][3],(self.pkg/rel).read_text())

    def test_upgrade_adds_new_defaults_once_without_reenabling_old_panel_choices(self):
        t.write_config({'initialized':True,'enabled':['direct-any-ip'],'aliases':[],'outbound':None})
        t.bootstrap()
        self.assertEqual(set(t.read_config()['enabled']),{'direct-any-ip',*t.performance.FEATURES})
        t.revert('rpxy-nodelay');t.bootstrap()
        self.assertNotIn('rpxy-nodelay',t.read_config()['enabled'])
        self.assertNotIn('cdn-same-ip',t.read_config()['enabled'])

    def test_unavailable_performance_does_not_block_panel_install(self):
        self.mocks[7].return_value=([],{'rpxy-nodelay':'BPF unavailable'})
        t.bootstrap()
        self.assertEqual(set(t.read_config()['enabled']),set(t.PANEL_DEFAULTS))
        self.assertEqual(t.read_config()['performance_defaults_skipped'],{'rpxy-nodelay':'BPF unavailable'})

    def test_performance_failure_rolls_back_source_and_choices(self):
        self.mocks[9].side_effect=[RuntimeError('BPF attach failed'),None]
        with self.assertRaisesRegex(RuntimeError,'BPF attach failed'):t.bootstrap()
        self.assertEqual(t.read_config()['enabled'],[])
        for feature,(rel,*_) in t.PATCHES.items():self.assertNotIn(t.PATCHES[feature][3],(self.pkg/rel).read_text())

    def test_explicit_installer_opt_out_survives_later_regular_install(self):
        with patch.dict(os.environ,{'HT_SKIP_PERFORMANCE_DEFAULTS':'1'}):t.bootstrap()
        t.bootstrap()
        self.assertEqual(set(t.read_config()['enabled']),set(t.PANEL_DEFAULTS))
        self.mocks[7].assert_not_called()

class NetworkTests(unittest.TestCase):
    def test_bad_ports_and_injections_refused(self):
        for text in ['22:80','8080:9000','65536:80','8080:80,8080:443','8080:80;reboot','08080:80','3306:80','']:
            with self.assertRaises(ValueError):t.parse_aliases(text)
        self.assertEqual(t.parse_aliases('8080:80,8443:443'),[[8080,80],[8443,443]])
    def test_outbound_requires_assigned_public_secondary(self):
        conf={'enabled':['outbound-ip'],'outbound':{'ip':'8.8.8.8','source':'46.62.164.112','interface':'eth0'}}
        with patch.object(t,'route_info',return_value=('eth0','46.62.164.112',['46.62.164.112'])):
            with self.assertRaises(ValueError):t.validate_outbound(conf)
        with patch.object(t,'route_info',return_value=('eth0','46.62.164.112',['46.62.164.112','8.8.8.8'])):t.validate_outbound(conf)
    def test_only_held_install_flock_counts_as_busy(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'0-install.lock';path.touch()
            self.assertFalse(t.installation_busy(Path(d)))
            with path.open() as stream:
                fcntl.flock(stream,fcntl.LOCK_EX)
                self.assertTrue(t.installation_busy(Path(d)))
            self.assertFalse(t.installation_busy(Path(d)))

    def test_boot_restore_does_not_require_gateway_already_listening(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'generated').mkdir();(root/'generated/firewall.sh').write_text('redirect_domain_ports "" ""\n')
            conf={'enabled':['port-alias'],'aliases':[[8080,80]]}
            with patch.object(t,'MANAGER',root),patch.object(t,'run',return_value=NS(stdout='')):
                with self.assertRaisesRegex(ValueError,'not listening'):t.validate_aliases(conf)
                t.validate_aliases(conf,require_listener=False)

    def test_version_12_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'VERSION').write_text('12.0.0')
            with patch.object(t,'MANAGER',root):
                with self.assertRaisesRegex(ValueError,'unsupported'):t.supported()

if __name__=='__main__':unittest.main()
