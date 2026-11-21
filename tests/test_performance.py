import importlib.util
import hashlib
from pathlib import Path
import json
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('performance_test',Path(__file__).resolve().parents[1]/'lib/performance.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)


class CapacityTests(unittest.TestCase):
    def test_ram_budget_and_page_size_and_small_host(self):
        self.assertEqual(p.capacity_floors(8*1024**3,4096),{'tcp-memory':'131072 196608 262144','tcp-timewait':'262144'})
        self.assertEqual(p.capacity_floors(2*1024**3,65536),{'tcp-memory':'2048 3072 4096','tcp-timewait':'65536'})
        with self.assertRaises(ValueError):p.capacity_floors(512*1024**2,4096)

    def test_unknown_os_skips_defaults_without_kernel_mutation(self):
        with patch.object(p,'host_check',side_effect=ValueError('unknown OS')),patch.object(p,'write_value') as write:
            defaults,skipped=p.eligible_defaults()
        self.assertEqual(defaults,[]);self.assertEqual(set(skipped),set(p.FEATURES));write.assert_not_called()

    def test_bpf_failure_skips_only_nodelay(self):
        with patch.object(p,'host_check'),patch.object(p,'read_value',return_value='5000'),patch.object(p,'probe_nodelay',side_effect=RuntimeError('BPF disabled')):
            defaults,skipped=p.eligible_defaults()
        self.assertEqual(defaults,['tcp-memory','tcp-timewait']);self.assertEqual(skipped,{'rpxy-nodelay':'BPF disabled'})


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.state=self.root/'state'
        self.sysfile=self.root/'sysctl.conf';self.dropin=self.root/'nodelay.conf';self.cg=self.root/'cgroup';self.cg.mkdir()
        self.runtime={'net.ipv4.tcp_mem':'25600 51200 102400','net.ipv4.tcp_max_tw_buckets':'5000'};self.original=dict(self.runtime)
        self.writes=[]
        self.patches=[patch.object(p,'SYSCTL_FILE',self.sysfile),patch.object(p,'DROPIN',self.dropin),
                      patch.object(p,'host_check',return_value=p.capacity_floors(8*1024**3,4096)),
                      patch.object(p,'read_value',side_effect=lambda k:self.runtime[k]),
                      patch.object(p,'write_value',side_effect=self.write),patch.object(p,'run',return_value=NS(returncode=0,stdout='')),patch.object(p,'probe_nodelay')]
        self.mocks=[x.start() for x in self.patches]
    def tearDown(self):
        for x in reversed(self.patches):x.stop()
        self.temp.cleanup()
    def write(self,key,value):
        self.runtime[key]=value;self.writes.append((key,value))
    def sync(self,*features):return p.sync({'enabled':list(features)},self.state,Path('/opt/hiddify-toolkit/lib/toolkit.py'))

    def test_independent_revert_idempotence_and_exact_originals(self):
        self.sync('tcp-memory','tcp-timewait');count=len(self.writes)
        self.sync('tcp-memory','tcp-timewait');self.assertEqual(len(self.writes),count)
        self.assertEqual(self.runtime['net.ipv4.tcp_mem'],'131072 196608 262144')
        self.assertTrue(p.status('tcp-memory',self.state))
        self.sync('tcp-memory');self.assertEqual(self.runtime['net.ipv4.tcp_max_tw_buckets'],'5000')
        self.assertIn('net.ipv4.tcp_mem',self.sysfile.read_text());self.assertNotIn('tcp_max_tw_buckets',self.sysfile.read_text())
        self.sync();self.assertEqual(self.runtime,self.original);self.assertFalse(self.sysfile.exists())

    def test_larger_existing_values_are_preserved(self):
        self.runtime['net.ipv4.tcp_mem']='262144 393216 524288';self.runtime['net.ipv4.tcp_max_tw_buckets']='524288';original=dict(self.runtime)
        self.sync('tcp-memory','tcp-timewait');self.assertEqual(self.runtime,original);self.assertEqual(self.writes,[])
        self.sync();self.assertEqual(self.runtime,original)

    def test_external_runtime_change_is_not_overwritten_on_revert(self):
        self.sync('tcp-timewait');self.runtime['net.ipv4.tcp_max_tw_buckets']='999999'
        self.sync();self.assertEqual(self.runtime['net.ipv4.tcp_max_tw_buckets'],'999999');self.assertFalse(self.sysfile.exists())

    def test_partial_sysctl_failure_restores_all_runtime_files_and_receipt(self):
        def fail(k,v):
            if k=='net.ipv4.tcp_max_tw_buckets' and v=='262144':raise RuntimeError('write failed')
            self.write(k,v)
        self.mocks[4].side_effect=fail
        with self.assertRaisesRegex(RuntimeError,'write failed'):self.sync('tcp-memory','tcp-timewait')
        self.assertEqual(self.runtime,self.original);self.assertFalse(self.sysfile.exists());self.assertFalse((self.state/'performance.json').exists())

    def test_bpf_attach_failure_restores_capacity_and_dropin(self):
        binary=self.root/'helper';binary.write_text('placeholder')
        def call(binary,action,group):
            if action=='status':return {'owned_attached':False}
            raise RuntimeError('BPF attach failed')
        with patch.object(p,'ensure_helper',return_value=(binary,True)),patch.object(p,'service_info',return_value=(123,self.cg)),patch.object(p,'helper',side_effect=call):
            with self.assertRaisesRegex(RuntimeError,'BPF attach failed'):self.sync('tcp-memory','rpxy-nodelay')
        self.assertEqual(self.runtime,self.original);self.assertFalse(self.dropin.exists());self.assertFalse(self.sysfile.exists())

    def test_unowned_or_missing_receipt_is_refused(self):
        self.sysfile.write_text('net.ipv4.tcp_mem = 9 10 11\n')
        with self.assertRaises(ValueError):self.sync('tcp-memory')
        self.assertEqual(self.runtime,self.original);self.assertEqual(self.writes,[])
        self.sysfile.write_text(p.MARKER+'net.ipv4.tcp_mem = 9 10 11\n')
        with self.assertRaisesRegex(ValueError,'receipt missing'):self.sync('tcp-memory')

    def test_helper_cache_cannot_be_reused_on_another_architecture(self):
        binary=self.state/'bin/tcp-nodelay';binary.parent.mkdir(parents=True);binary.write_bytes(b'test executable')
        receipt={'machine':p.platform.machine(),'source_sha256':hashlib.sha256(p.SOURCE.read_bytes()).hexdigest(),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
        path=self.state/'performance-helper.json';path.write_text(json.dumps(receipt));self.assertTrue(p.valid_helper(self.state))
        receipt['machine']='another-machine';path.write_text(json.dumps(receipt));self.assertFalse(p.valid_helper(self.state))

    def test_boot_pending_is_completed_in_rpxy_service_cgroup(self):
        binary=self.root/'helper';binary.write_text('placeholder')
        with patch.object(p,'ensure_helper',return_value=(binary,False)),patch.object(p,'service_info',return_value=(0,None)):
            result=self.sync('rpxy-nodelay')
        self.assertTrue(result['pending_rpxy_start']);self.assertIn('performance-prepare',self.dropin.read_text())
        with patch.object(p,'ensure_helper',return_value=(binary,False)),patch.object(p,'service_info',return_value=(0,self.cg)),patch.object(p,'helper',return_value={'owned_attached':True,'owned_program_ids':[1]}):
            result=self.sync('rpxy-nodelay')
        self.assertTrue(result['attachment']['owned_attached']);self.assertNotIn('pending_rpxy_start',result)

    def test_repaired_attachment_updates_existing_sockets_without_restart(self):
        binary=self.root/'helper';binary.write_text('placeholder');events=[]
        def helper(binary,action,group):
            events.append(action);return {'owned_attached':action!='status','owned_program_ids':[1] if action!='status' else []}
        with patch.object(p,'ensure_helper',return_value=(binary,False)),patch.object(p,'service_info',return_value=(123,self.cg)),patch.object(p,'helper',side_effect=helper),patch.object(p,'socket_options',return_value={'on':5}) as scan:
            self.sync('rpxy-nodelay');self.sync('rpxy-nodelay')
        self.assertEqual(events,['status','attach','status','attach']);self.assertEqual(scan.call_count,2)


if __name__=='__main__':unittest.main()
