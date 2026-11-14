"""Temporary authored metadata fixtures; no game data or deletion authorization."""
import contextlib
import ctypes
import io
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from tools import storage_audit as storage


class AllocationAPI:
    def __init__(self,size,*,failure=None):
        self.size=size;self.failure=failure;self.closed=[];self.created=[]

    def CreateFileW(self,*arguments):
        self.created.append(arguments)
        return ctypes.c_void_p(-1).value if self.failure=="create" else 77

    def GetFileInformationByHandleEx(self,handle,kind,output,size):
        if kind==9:
            if self.failure=="tag_api":return 0
            value=ctypes.cast(output,ctypes.POINTER(storage._FileAttributeTagInfo)).contents
            value.FileAttributes=0x400 if self.failure=="reparse" else 0x80
            value.ReparseTag=0xA0000003 if self.failure=="reparse" else 0
        elif kind==1:
            if self.failure=="standard_api":return 0
            value=ctypes.cast(output,ctypes.POINTER(storage._FileStandardInfo)).contents
            value.AllocationSize=-1 if self.failure=="negative" else 8192
            value.EndOfFile=self.size+1 if self.failure=="eof" else self.size
            value.NumberOfLinks=1;value.Directory=self.failure=="directory";value.DeletePending=self.failure=="pending"
        else:raise AssertionError("unexpected information class")
        return 1

    def CloseHandle(self,handle):
        self.closed.append(handle)
        return self.failure!="close"

    def GetLastError(self):return 6


class StorageAuditTests(unittest.TestCase):
    def fixture(self):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
        return Path(directory.name)

    def write(self,root,name,size):
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b"x"*size)
        return path

    def audit(self,roots,**options):
        return storage.audit(roots,allocation_reader=lambda path:4096 if os.lstat(path).st_size else 0,**options)

    def test_all_directory_levels_workspace_repo_and_extensions_have_explicit_units(self):
        root=self.fixture();self.write(root,"repo/deep/a.OBJ",9);self.write(root,"repo/root.txt",3);self.write(root,".venv/dependency.bin",5)
        report=self.audit([root],repo_paths=[root/"repo"])
        self.assertEqual(report["totals"]["logical_bytes_by_path"],17)
        self.assertEqual(report["totals"]["logical_bytes_unique_observed"],17)
        self.assertEqual(report["workspace_roots"][0]["totals"]["file_paths"],3)
        self.assertEqual(report["repo_roots"][0]["totals"]["logical_bytes_by_path"],12)
        by_path={item["path"]:item for item in report["directories"]}
        self.assertEqual(by_path[str(root/"repo/deep")]["logical_bytes_by_path"],9)
        self.assertEqual(by_path[str(root/"repo")]["direct_files"],1)
        self.assertEqual(by_path[str(root)]["descendant_directories"],3)
        extensions={item["extension"]:item for item in report["extensions"]}
        self.assertEqual(extensions[".obj"]["logical_bytes_by_path"],9)
        self.assertIsNone(report["totals"]["estimated_reclaimable_bytes"])

    def test_attribute_handle_uses_no_follow_rights_and_closes_once(self):
        root=self.fixture();path=self.write(root,"plain.bin",5);api=AllocationAPI(5)
        self.assertEqual(ctypes.sizeof(storage._FileStandardInfo),24)
        self.assertEqual(storage.allocated_size(str(path),api=api),8192)
        self.assertEqual(api.created[0],(str(path),0x80,7,None,3,0x00200000,None))
        self.assertEqual(api.closed,[77])

    def test_allocation_api_failures_reparse_or_invalid_metadata_are_unknown_and_closed(self):
        root=self.fixture();path=self.write(root,"plain.bin",5)
        for failure in ("create","tag_api","standard_api","reparse","directory","pending","negative","eof","close"):
            with self.subTest(failure=failure):
                api=AllocationAPI(5,failure=failure)
                report=storage.audit([root],allocation_reader=lambda name:storage.allocated_size(name,api=api))
                self.assertEqual(report["totals"]["errors"],1)
                self.assertEqual(report["totals"]["allocated_unknown_unique_observed"],1)
                self.assertIsNone(report["top30_files"][0]["allocated_bytes"])
                self.assertEqual(api.closed,[] if failure=="create" else [77])

    @unittest.skipUnless(os.name=="nt","actual NTFS allocation metadata is Windows-only")
    def test_native_ntfs_tiny_and_small_nonresident_allocations_use_real_cluster_unit(self):
        root=self.fixture();anchor=Path(root).anchor;kernel=ctypes.WinDLL("kernel32",use_last_error=True)
        dword=ctypes.c_uint32;pointer=ctypes.POINTER(dword)
        kernel.GetVolumeInformationW.argtypes=(ctypes.c_wchar_p,ctypes.c_wchar_p,dword,pointer,pointer,pointer,ctypes.c_wchar_p,dword)
        kernel.GetVolumeInformationW.restype=ctypes.c_int
        filesystem=ctypes.create_unicode_buffer(32)
        self.assertTrue(kernel.GetVolumeInformationW(anchor,None,0,None,None,None,filesystem,len(filesystem)))
        if filesystem.value.upper()!="NTFS":self.skipTest("fixture volume is not NTFS")
        kernel.GetDiskFreeSpaceW.argtypes=(ctypes.c_wchar_p,pointer,pointer,pointer,pointer);kernel.GetDiskFreeSpaceW.restype=ctypes.c_int
        sectors=dword();sector_bytes=dword();free=dword();total=dword()
        self.assertTrue(kernel.GetDiskFreeSpaceW(anchor,ctypes.byref(sectors),ctypes.byref(sector_bytes),ctypes.byref(free),ctypes.byref(total)))
        unit=sectors.value*sector_bytes.value;self.assertGreater(unit,0)
        tiny=self.write(root,"tiny.bin",1)
        tiny_allocation=storage.allocated_size(str(tiny))
        self.assertGreaterEqual(tiny_allocation,tiny.stat().st_size)
        # Tiny NTFS resident streams need not allocate an entire cluster. Use a
        # small nonresident payload for the independent cluster-multiple check.
        small=self.write(root,"small-nonresident.bin",max(unit,1024)+1)
        allocation=storage.allocated_size(str(small))
        self.assertGreaterEqual(allocation,small.stat().st_size)
        self.assertEqual(allocation%unit,0)
        report=storage.audit([root])
        self.assertEqual(report["totals"]["allocated_unknown_unique_observed"],0)
        self.assertEqual(report["totals"]["allocated_bytes_known_unique_observed"],allocation+tiny_allocation)
        self.assertIn("FileStandardInfo",report["allocated_size_method"])

    def test_allocated_unavailable_is_unknown_not_zero_or_reclaimable(self):
        root=self.fixture();self.write(root,"plain",11)
        report=storage.audit([root],allocation_reader=lambda path:None)
        self.assertEqual(report["totals"]["allocated_unknown_unique_observed"],1)
        self.assertEqual(report["top30_files"][0]["allocated_bytes"],None)
        self.assertEqual(report["totals"]["logical_bytes_by_path"],11)
        self.assertIsNone(report["totals"]["estimated_reclaimable_bytes"])
        self.assertFalse(report["deletion_authorized"])

    def test_hardlinks_deduplicate_across_roots_without_claiming_external_links_freed(self):
        root=self.fixture();one=root/"one";two=root/"two";outside=root/"outside"
        one.mkdir();two.mkdir();outside.mkdir()
        first=self.write(one,"movie.mix",101)
        os.link(first,two/"alias.mix");os.link(first,outside/"not_scanned.mix")
        report=self.audit([one,two])
        self.assertEqual(report["totals"]["file_paths"],2)
        self.assertEqual(report["totals"]["logical_bytes_by_path"],202)
        self.assertEqual(report["totals"]["logical_bytes_unique_observed"],101)
        self.assertEqual(report["totals"]["allocated_bytes_known_unique_observed"],4096)
        self.assertEqual(report["hardlink_groups"][0]["observed_aliases"],2)
        self.assertTrue(report["hardlink_groups"][0]["external_links_possible"])
        self.assertIsNone(report["hardlink_groups"][0]["estimated_reclaimable_bytes"])
        self.assertEqual(report["review_plan"],[])

    def test_unique_top_and_mixed_extension_groups_count_each_identity_once(self):
        root=self.fixture();first=self.write(root,"asset.mix",101)
        os.link(first,root/"alias.obj");self.write(root,"independent.pdb",50)
        report=self.audit([root])
        self.assertEqual(len(report["top30_files"]),3);self.assertEqual(len(report["top30_unique_files"]),2)
        largest=report["top30_unique_files"][0]
        self.assertEqual((largest["logical_bytes"],largest["observed_aliases"]),(101,2))
        self.assertEqual(largest["extensions"],[".mix",".obj"])
        categories={item["extension"]:item for item in report["extensions_unique_observed"]}
        self.assertEqual(categories["[mixed suffixes]"]["logical_bytes_unique_observed"],101)
        self.assertEqual(categories[".pdb"]["logical_bytes_unique_observed"],50)
        self.assertEqual(sum(item["logical_bytes_unique_observed"] for item in categories.values()),151)
        self.assertFalse(any(item["path"]==str(root/"alias.obj") for item in report["review_plan"]))
        self.assertIn("Top 30 unique observed files",storage.markdown(report))
        self.assertIn("[mixed suffixes]",storage.markdown(report))

    def test_nested_explicit_roots_are_not_rescanned_or_double_counted(self):
        root=self.fixture();self.write(root,"repo/a.bin",7)
        report=self.audit([root/"repo",root,root])
        self.assertEqual(report["totals"]["file_paths"],1)
        self.assertEqual(report["totals"]["logical_bytes_by_path"],7)
        self.assertEqual(len(report["workspace_roots"]),2)
        self.assertEqual(report["workspace_roots"][1]["status"],"covered_by_outer_explicit_root")

    def test_allowlist_and_absolute_roots_cannot_silently_expand_scan(self):
        root=self.fixture();inside=root/"inside";outside=root/"outside";inside.mkdir();outside.mkdir()
        with self.assertRaises(ValueError):self.audit([outside],allowed_roots=[inside])
        with self.assertRaises(ValueError):self.audit(["relative"])
        with self.assertRaises(ValueError):self.audit([inside],repo_paths=[outside])
        report=self.audit([inside],allowed_roots=[root])
        self.assertEqual(report["totals"]["file_paths"],0)
        self.assertEqual(report["requested_roots"],[str(inside)])

    def test_symlink_or_junction_targets_and_root_ancestors_are_not_traversed(self):
        root=self.fixture();inside=root/"inside";outside=root/"outside";inside.mkdir();outside.mkdir()
        self.write(inside,"local.txt",3);self.write(outside,"secret.dat",100)
        link=inside/"linked"
        try:os.symlink(outside,link,target_is_directory=True)
        except OSError:
            if os.name!="nt":raise
            result=subprocess.run(["cmd.exe","/d","/c","mklink","/J",str(link),str(outside)],capture_output=True)
            if result.returncode:self.skipTest("temporary reparse fixture is unavailable")
        reads=[]
        report=storage.audit([inside],allocation_reader=lambda path:reads.append(path) or 4096)
        self.assertEqual(report["totals"]["logical_bytes_by_path"],3)
        self.assertEqual(report["totals"]["link_entries"],1)
        self.assertFalse(report["links"][0]["traversed"])
        self.assertEqual(reads,[str(inside/"local.txt")])
        linked_root=storage.audit([link],allocation_reader=lambda path:self.fail("root link target read"))
        self.assertEqual(linked_root["totals"]["file_paths"],0)
        self.assertEqual(linked_root["workspace_roots"][0]["status"],"reparse_root_or_ancestor_not_traversed")
        child_root=storage.audit([link/"nested"],allocation_reader=lambda path:self.fail("link ancestor target read"))
        self.assertEqual(child_root["totals"]["file_paths"],0)
        self.assertEqual(child_root["links"][0]["path"],str(link))

    @unittest.skipUnless(os.name=="nt","native junction fixture is Windows-only")
    def test_native_windows_junction_tag_and_descendant_root_are_never_followed(self):
        root=self.fixture();owned=root/"owned";outside=root/"outside";owned.mkdir();outside.mkdir()
        self.write(outside,"nested/sentinel.bin",99)
        link=owned/"junction"
        result=subprocess.run(["cmd.exe","/d","/c","mklink","/J",str(link),str(outside)],capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors="replace"))
        self.assertEqual(os.lstat(link).st_reparse_tag,0xA0000003)
        report=storage.audit([owned],allocation_reader=lambda path:self.fail("junction target allocation read"))
        self.assertEqual(report["totals"]["file_paths"],0);self.assertEqual(report["totals"]["link_entries"],1)
        ancestor=storage.audit([link/"nested"],allocation_reader=lambda path:self.fail("junction ancestor allocation read"))
        self.assertEqual(ancestor["totals"]["file_paths"],0)
        self.assertEqual(ancestor["links"][0]["path"],str(link))
        self.assertFalse(ancestor["links"][0]["traversed"])

    def test_reparse_attribute_is_rejected_even_without_symlink_mode(self):
        fake=SimpleNamespace(st_mode=stat.S_IFDIR,st_file_attributes=0x400,st_reparse_tag=0xA0000003)
        self.assertTrue(storage.is_link(fake))
        plain=SimpleNamespace(st_mode=stat.S_IFDIR,st_file_attributes=0)
        self.assertFalse(storage.is_link(plain))

    def test_git_objects_resources_current_host_environment_and_keep_paths_are_never_candidates(self):
        root=self.fixture()
        for name in (".git/objects/a.obj","game/cache.obj","build/current.obj",".venv/pkg/cache.pyc","work/trigger-lifecycle-hosts/old/debug.obj","movie.mix","gamemd.exe"):
            self.write(root,name,17)
        self.write(root,"build/rebuild.obj",19)
        keep=root/"build/current.obj"
        report=self.audit([root],keep_paths=[keep])
        candidates={item["path"] for item in report["review_plan"]}
        self.assertEqual(candidates,{str(root/"build/rebuild.obj")})
        self.assertTrue(all(item["action"]=="review_only" and not item["deletion_authorized"] and item["estimated_reclaimable_bytes"] is None for item in report["review_plan"]))
        protected={item["path"]:item["protected_reasons"] for item in report["top30_files"]}
        self.assertIn("explicit_keep",protected[str(keep)])
        self.assertIn("git_objects_or_metadata",protected[str(root/".git/objects/a.obj")])

    def test_top_limits_extensions_and_zero_size_files_are_accounted(self):
        root=self.fixture()
        for index in range(35):self.write(root,f"d{index}/file{index}.dat",index)
        report=self.audit([root])
        self.assertEqual(len(report["top30_files"]),30);self.assertEqual(len(report["top20_directories"]),20)
        self.assertEqual(report["top30_files"][0]["logical_bytes"],34)
        self.assertEqual(report["totals"]["file_paths"],35)
        self.assertEqual(report["extensions"][0]["file_paths"],35)
        self.assertEqual(report["totals"]["logical_bytes_by_path"],sum(range(35)))

    def test_allocation_failure_is_recorded_without_calling_file_deletable(self):
        root=self.fixture();self.write(root,"a.obj",8)
        def unavailable(path):raise PermissionError("authored metadata refusal")
        report=storage.audit([root],allocation_reader=unavailable)
        self.assertFalse(report["logical_inventory_complete"])
        self.assertEqual(report["totals"]["file_paths"],1)
        self.assertEqual(report["totals"]["errors"],1)
        self.assertEqual(report["totals"]["allocated_unknown_unique_observed"],1)
        self.assertFalse(report["deletion_authorized"])

    def test_changed_file_during_allocated_read_marks_metrics_incomplete(self):
        root=self.fixture();path=self.write(root,"growing.log",5)
        def changing(_):path.write_bytes(b"changed length");return 4096
        report=storage.audit([root],allocation_reader=changing)
        self.assertEqual(report["totals"]["errors"],1)
        self.assertEqual(report["top30_files"][0]["allocated_bytes"],None)
        self.assertFalse(report["logical_inventory_complete"])

    def test_missing_root_is_explicit_and_does_not_imply_empty_success(self):
        root=self.fixture();report=self.audit([root/"missing"])
        self.assertFalse(report["logical_inventory_complete"])
        self.assertEqual(report["workspace_roots"][0]["status"],"unavailable")
        self.assertGreater(report["totals"]["errors"],0)

    def test_cli_writes_only_new_report_directory_and_never_overwrites(self):
        root=self.fixture();self.write(root,"evidence.txt",7);output=root/"new-report"
        before=(root/"evidence.txt").read_bytes()
        with contextlib.redirect_stdout(io.StringIO()):
            storage.main(["--root",str(root),"--out-dir",str(output)])
        report=json.loads((output/"inventory.json").read_text(encoding="utf-8"))
        self.assertEqual(report["totals"]["file_paths"],1)
        self.assertIn("Reclaimable bytes: UNKNOWN",(output/"inventory.md").read_text(encoding="utf-8"))
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
            storage.main(["--root",str(root),"--out-dir",str(output)])
        self.assertEqual((root/"evidence.txt").read_bytes(),before)
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
            storage.main(["--root",str(root),"--delete"])


    def test_fifty_largest_files_thirty_directories_and_unique_path_categories(self):
        root=self.fixture()
        for index in range(60):self.write(root,f"dir{index}/file{index}.dat",index+1)
        generated=self.write(root,"src/recomp/gen/generated.c",100)
        os.link(generated,root/"protected.mix")
        report=self.audit([root])
        self.assertEqual(len(report['top50_files']),50)
        self.assertEqual(len(report['top30_files']),30)
        self.assertEqual(len(report['top30_directories']),30)
        self.assertEqual(len(report['top50_unique_files']),50)
        categories={row['category']:row for row in report['categories_unique_observed']}
        self.assertEqual(categories['mixed_path_categories_review']['logical_bytes_unique_observed'],100)
        self.assertEqual(sum(row['logical_bytes_unique_observed']for row in categories.values()),report['totals']['logical_bytes_unique_observed'])
        self.assertIsNone(report['totals']['estimated_reclaimable_bytes'])
        self.assertFalse(report['deletion_authorized'])
        self.assertIn('Top 50 files',storage.markdown(report))

    def test_path_classification_never_promotes_unverified_cache_to_deletion(self):
        root=self.fixture()
        for name in ('src/recomp/gen/old.c','work/build-cache/a.obj','work/session/state.bin','game/resource.mix','work/power-target-hosts/x/identity.json'):
            self.write(root,name,4)
        report=self.audit([root]);files={x['path']:x for x in report['top50_files']}
        self.assertEqual(files[str(root/'src/recomp/gen/old.c')]['category'],'generated_source_unclassified_current_or_old')
        self.assertEqual(files[str(root/'work/build-cache/a.obj')]['category'],'object_unclassified_current_or_old')
        self.assertEqual(files[str(root/'work/session/state.bin')]['category'],'world_state_binary')
        self.assertIn('frozen_host_evidence',files[str(root/'work/power-target-hosts/x/identity.json')]['protected_reasons'])
        self.assertTrue(all(not x['deletion_authorized'] for x in report['review_plan']))

    def test_previous_inventory_growth_requires_complete_same_scope(self):
        root=self.fixture();self.write(root,'a.dat',5)
        old=self.audit([root]);self.write(root,'b.dat',10);new=self.audit([root])
        result=storage.growth_comparison(old,new)
        self.assertEqual(result['status'],'COMPARABLE')
        self.assertEqual(result['logical_delta_bytes'],10)
        self.assertEqual(result['allocated_delta_bytes'],4096)
        unknown=json.loads(json.dumps(old));unknown['totals']['allocated_unknown_unique_observed']=1
        self.assertEqual(storage.growth_comparison(unknown,new)['status'],'PARTIAL')
        self.assertIsNone(storage.growth_comparison(unknown,new)['allocated_delta_bytes'])
        wrong=json.loads(json.dumps(old));wrong['requested_roots']=[str(root/'other')]
        self.assertEqual(storage.growth_comparison(wrong,new)['status'],'UNKNOWN')
        wrong=json.loads(json.dumps(old));wrong['logical_inventory_complete']=False
        self.assertEqual(storage.growth_comparison(wrong,new)['status'],'UNKNOWN')
        self.assertEqual(storage.growth_comparison(None,new)['status'],'UNKNOWN')
        wrong=json.loads(json.dumps(old));wrong['totals']['hardlink_identity_unavailable_paths']=1
        self.assertEqual(storage.growth_comparison(wrong,new)['status'],'UNKNOWN')
        wrong=json.loads(json.dumps(old));wrong['allocated_size_method']='different method'
        self.assertEqual(storage.growth_comparison(wrong,new)['status'],'PARTIAL')
        self.assertIsNone(storage.growth_comparison(wrong,new)['allocated_delta_bytes'])

    def test_advisory_low_volume_and_growth_do_not_execute_actions(self):
        report={'volumes':[{'volume':'E:', 'free_bytes':99}], 'growth':{'status':'COMPARABLE','allocated_delta_bytes':101}}
        advisory=storage.recommendations(report,low_space_bytes=100,growth_bytes=100)
        self.assertEqual([x['kind']for x in advisory['warnings']],['LOW_VOLUME_SPACE','PROJECT_GROWTH_SINCE_PREVIOUS_INVENTORY'])
        self.assertFalse(advisory['automatically_deletes']);self.assertFalse(advisory['enforces_generation_limit'])
        report['growth']={'status':'PARTIAL','allocated_delta_bytes':None}
        self.assertEqual(len(storage.recommendations(report,low_space_bytes=100,growth_bytes=100)['warnings']),1)
        with self.assertRaises(ValueError):storage.recommendations(report,low_space_bytes=-1)

    def test_size_collisions_are_never_claimed_as_duplicate_content(self):
        root=self.fixture();self.write(root,'one.dat',3);self.write(root,'two.dat',3)
        report=self.audit([root]);row=report['size_collision_groups'][0]
        self.assertEqual((row['logical_bytes'],row['distinct_file_identities']),(3,2))
        self.assertIsNone(row['content_equal']);self.assertIsNone(report['totals']['estimated_reclaimable_bytes'])


    def test_content_sha_opt_in_distinguishes_hardlinks_independent_copies_and_different_bytes(self):
        root=self.fixture();a=self.write(root,'base.mix',5);b=self.write(root,'copy.mix',5)
        different=root/'different.mix';different.write_bytes(b'yyyyy');os.link(a,root/'alias.mix')
        self.write(root,'same-size.ini',5)
        with mock.patch.object(storage,'_stable_content_sha256',side_effect=AssertionError('default must never hash')):
            disabled=self.audit([root]);self.assertEqual(disabled['content_duplicates']['status'],'DISABLED')
        result=self.audit([root],hash_duplicate_suffixes=['.MIX']);report=result['content_duplicates']
        self.assertEqual(report['status'],'COMPLETE');self.assertEqual(report['identities_hashed'],3)
        self.assertEqual(len(report['groups']),1);group=report['groups'][0]
        self.assertEqual(group['sha256'],hashlib.sha256(b'xxxxx').hexdigest())
        self.assertEqual(group['independent_file_identities'],2);self.assertEqual(group['observed_alias_paths'],3)
        self.assertEqual(group['allocated_bytes_known_unique_observed'],8192)
        self.assertTrue(all('game_resource_or_executable' in x['protected_reasons'] for x in group['identities']))
        self.assertIsNone(group['estimated_reclaimable_bytes']);self.assertFalse(group['deletion_authorized'])
        self.assertEqual(a.read_bytes(),b.read_bytes());self.assertEqual(different.read_bytes(),b'yyyyy')
        alert=storage.recommendations(result,duplicate_bytes=100)
        self.assertIn('DUPLICATE_CONTENT_REVIEW',[x['kind']for x in alert['warnings']])

    def test_content_sha_marks_sharing_or_changed_identity_partial_without_false_group(self):
        root=self.fixture();self.write(root,'a.mix',10);self.write(root,'b.mix',10)
        real=storage._stable_content_sha256
        def changed(path,expected):
            Path(path).write_bytes(b'q'*10)
            return real(path,expected)
        with mock.patch.object(storage,'_stable_content_sha256',side_effect=changed):
            report=self.audit([root],hash_duplicate_suffixes=['.mix'])['content_duplicates']
        self.assertEqual(report['status'],'PARTIAL');self.assertEqual(report['groups'],[]);self.assertEqual(len(report['errors']),2)
        with mock.patch.object(storage,'_stable_content_sha256',side_effect=PermissionError('file in use')):
            report=self.audit([root],hash_duplicate_suffixes=['.mix'])['content_duplicates']
        self.assertEqual(report['status'],'PARTIAL');self.assertEqual(report['groups'],[])
        self.assertFalse(report['deletion_authorized'])

    def test_content_sha_retains_external_hardlink_and_no_follow_policy(self):
        root=self.fixture();outside=self.fixture();source=self.write(root,'a.mix',6);self.write(root,'b.mix',6)
        os.link(source,outside/'external.mix')
        report=self.audit([root],hash_duplicate_suffixes=['.mix'])['content_duplicates']
        self.assertEqual(report['status'],'COMPLETE');group=report['groups'][0]
        self.assertTrue(any(x['external_links_possible'] for x in group['identities']))
        self.assertIsNone(group['estimated_reclaimable_bytes'])
        with self.assertRaises(ValueError):self.audit([root],hash_duplicate_suffixes=['../mix'])
        with self.assertRaises(ValueError):storage.content_duplicate_report([], [None])

    def test_cli_explicit_content_sha_remains_report_only(self):
        root=self.fixture();self.write(root,'a.mix',3);self.write(root,'b.mix',3);out=root/'result'
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(storage.main(['--root',str(root),'--hash-duplicates','.mix','--out-dir',str(out)]),0)
        report=json.loads((out/'inventory.json').read_text(encoding='utf8'))
        self.assertEqual(report['content_duplicates']['status'],'COMPLETE')
        self.assertEqual(len(report['content_duplicates']['groups']),1)
        self.assertIn('Content duplicate SHA review',(out/'inventory.md').read_text(encoding='utf8'))
        self.assertEqual((root/'a.mix').read_bytes(),b'xxx');self.assertFalse(report['deletion_authorized'])



if __name__=="__main__":unittest.main()
