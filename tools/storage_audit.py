"""Read-only storage inventory. No removal, mutation or reclamation API.

Logical lengths and allocated/compressed lengths are observations, never bytes
that deleting a path would free. Hard links are deduplicated by file identity;
links/reparse points are inventoried without traversing their targets. Metadata
can change during a scan: this is not an atomic filesystem snapshot.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import ctypes
from datetime import datetime, timezone
import heapq
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import time

REPARSE_POINT=0x400
SPARSE_FILE=0x200
COMPRESSED_FILE=0x800
RESOURCE_SUFFIXES={".exe",".dll",".mix",".bik",".vqa",".shp",".pal",".csf",".map",".mpr",".yrm",".sav",".aud",".wav",".mp3",".ogg",".ini"}
DERIVED_SUFFIXES={".obj",".o",".pch",".ipch",".ilk",".tmp",".cache",".pyc"}
_ALLOCATED_API=None


def absolute(path):
    value=os.fspath(path)
    if not os.path.isabs(value):raise ValueError("explicit absolute paths are required")
    return os.path.normpath(os.path.abspath(value))


def within(path,parent):
    try:return os.path.normcase(os.path.commonpath((path,parent)))==os.path.normcase(parent)
    except ValueError:return False


def is_link(metadata):
    return stat.S_ISLNK(metadata.st_mode) or bool(getattr(metadata,"st_file_attributes",0)&REPARSE_POINT)


def file_identity(metadata):
    device=getattr(metadata,"st_dev",None);inode=getattr(metadata,"st_ino",None)
    return (device,inode) if type(device) is int and type(inode) is int and inode!=0 else None


class _FileStandardInfo(ctypes.Structure):
    _fields_=[("AllocationSize",ctypes.c_longlong),("EndOfFile",ctypes.c_longlong),
              ("NumberOfLinks",ctypes.c_uint32),("DeletePending",ctypes.c_ubyte),("Directory",ctypes.c_ubyte)]


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_=[("FileAttributes",ctypes.c_uint32),("ReparseTag",ctypes.c_uint32)]


def _allocation_api():
    global _ALLOCATED_API
    if _ALLOCATED_API is None:
        kernel=ctypes.WinDLL("kernel32",use_last_error=True)
        kernel.CreateFileW.argtypes=(ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p)
        kernel.CreateFileW.restype=ctypes.c_void_p
        kernel.GetFileInformationByHandleEx.argtypes=(ctypes.c_void_p,ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32)
        kernel.GetFileInformationByHandleEx.restype=ctypes.c_int
        kernel.CloseHandle.argtypes=(ctypes.c_void_p,);kernel.CloseHandle.restype=ctypes.c_int
        kernel.GetLastError.argtypes=();kernel.GetLastError.restype=ctypes.c_uint32
        _ALLOCATED_API=kernel
    return _ALLOCATED_API


def allocated_size(path,*,api=None):
    """Read FILE_STANDARD_INFO.AllocationSize through a no-follow handle.

    This observes allocated storage, not exclusively owned extents or deletion
    savings. Non-Windows hosts return unavailable. The optional API seam is for
    authored failure tests only and is never a fallback for failed real reads.
    """
    if api is None and os.name!="nt":return None
    kernel=_allocation_api() if api is None else api
    handle=kernel.CreateFileW(path,0x80,7,None,3,0x00200000,None)
    if handle in (None,0,ctypes.c_void_p(-1).value):raise OSError(kernel.GetLastError(),"CreateFileW attribute handle unavailable",path)
    try:
        tag=_FileAttributeTagInfo()
        if not kernel.GetFileInformationByHandleEx(handle,9,ctypes.byref(tag),ctypes.sizeof(tag)):
            raise OSError(kernel.GetLastError(),"FileAttributeTagInfo unavailable",path)
        if tag.FileAttributes&REPARSE_POINT or tag.ReparseTag:
            raise RuntimeError("reparse handle allocation is refused")
        standard=_FileStandardInfo()
        if not kernel.GetFileInformationByHandleEx(handle,1,ctypes.byref(standard),ctypes.sizeof(standard)):
            raise OSError(kernel.GetLastError(),"FileStandardInfo unavailable",path)
        if standard.Directory or standard.DeletePending or standard.AllocationSize<0 or standard.EndOfFile<0:
            raise RuntimeError("directory, delete-pending or malformed allocation handle refused")
        current=os.lstat(path)
        if is_link(current) or not stat.S_ISREG(current.st_mode) or standard.EndOfFile!=current.st_size:
            raise RuntimeError("handle EOF and no-follow path metadata differ")
        return standard.AllocationSize
    finally:
        if not kernel.CloseHandle(handle):raise OSError(kernel.GetLastError(),"CloseHandle failed after allocation observation",path)


def protection(path,*,keep_paths=()):
    parts=[part.casefold() for part in Path(path).parts];suffix=Path(path).suffix.casefold();reasons=[]
    if ".git" in parts:reasons.append("git_objects_or_metadata")
    if any(part in (".venv","venv") for part in parts):reasons.append("current_dependency_environment")
    if "game" in parts or suffix in RESOURCE_SUFFIXES:reasons.append("game_resource_or_executable")
    if any(part in ("trigger-lifecycle-hosts","power-target-hosts") for part in parts):reasons.append("frozen_host_evidence")
    if any(word in Path(path).name.casefold() for word in ("seal","ticket","generation-manifest")):reasons.append("identity_chain_review")
    if any(within(path,keep) for keep in keep_paths):reasons.append("explicit_keep")
    return sorted(set(reasons))


def classify(path):
    """Descriptive path category only: never infer removability or provenance."""
    parts=[part.casefold() for part in Path(path).parts]
    name=Path(path).name.casefold();suffix=Path(path).suffix.casefold()
    if '.git' in parts:return 'git_metadata'
    if suffix=='.mix':return 'mix_resource_protected'
    if any(part in ('.venv','venv') for part in parts):return 'python_environment'
    if suffix in ('.mp4','.avi','.mkv','.webm','.mov'):return 'video'
    if suffix in ('.bmp','.png','.jpg','.jpeg','.webp'):return 'image_or_frame'
    if name in ('state.bin','world.bin') or ('world' in name and suffix in ('.bin','.dat')):return 'world_state_binary'
    if suffix in ('.obj','.o'):return 'object_unclassified_current_or_old'
    if suffix in ('.pdb','.ilk','.lib','.pch','.ipch'):return 'compiler_intermediate_unclassified'
    if suffix in ('.c','.cc','.cpp','.cxx','.h','.hpp'):
        if any(part in ('gen','generated','generated-c','recomp-gen') or part.startswith('gen-') for part in parts):return 'generated_source_unclassified_current_or_old'
        return 'source'
    if suffix in ('.exe','.dll'):return 'executable_or_library_protected'
    if suffix in ('.log','.jsonl'):return 'logs'
    if suffix in ('.json','.csv','.md','.txt','.xml','.yml','.yaml','.toml'):return 'reports_or_metadata'
    if any(part in ('build-cache','cache','caches') for part in parts):return 'cache_unclassified'
    if suffix in RESOURCE_SUFFIXES:return 'game_resource_protected'
    if suffix in ('.bin','.dat'):return 'other_binary_evidence_unclassified'
    return 'other_unclassified'


def growth_comparison(previous,current):
    """One strictly comparable measurement, not a prediction or deletion plan."""
    unavailable=dict(status='UNKNOWN',logical_delta_bytes=None,allocated_delta_bytes=None,reason='no comparable prior complete inventory')
    if not isinstance(previous,dict):return unavailable
    try:
        if previous['schema']!='yr-storage-audit-v1' or current['schema']!='yr-storage-audit-v1':return unavailable
        if {os.path.normcase(absolute(x)) for x in previous['requested_roots']}!={os.path.normcase(absolute(x)) for x in current['requested_roots']}:return dict(unavailable,reason='audit roots differ')
        if not previous['logical_inventory_complete'] or not current['logical_inventory_complete']:return dict(unavailable,reason='one inventory is incomplete')
        a=previous['totals'];b=current['totals']
        if any(v.get('hardlink_identity_unavailable_paths')!=0 for v in (a,b)):return dict(unavailable,reason='one inventory has unavailable file identities')
        keys=('logical_bytes_unique_observed','allocated_bytes_known_unique_observed','allocated_unknown_unique_observed')
        if not all(type(v[k]) is int and v[k]>=0 for v in (a,b) for k in keys):return unavailable
        logical=b[keys[0]]-a[keys[0]]
        if a[keys[2]] or b[keys[2]]:return dict(status='PARTIAL',logical_delta_bytes=logical,allocated_delta_bytes=None,reason='allocation metadata unavailable for some identities')
        if previous.get('allocated_size_method')!=current.get('allocated_size_method'):return dict(status='PARTIAL',logical_delta_bytes=logical,allocated_delta_bytes=None,reason='allocation measurement methods differ')
        return dict(status='COMPARABLE',logical_delta_bytes=logical,allocated_delta_bytes=b[keys[1]]-a[keys[1]],reason='same roots, both inventories complete; live inventories are non-atomic')
    except (KeyError,TypeError,ValueError,OSError):return unavailable


def recommendations(report,*,low_space_bytes=20*1024**3,growth_bytes=10*1024**3,duplicate_bytes=10*1024**3):
    """Advisory only: callers implementing a preflight must enforce it separately."""
    if any(type(value) is not int or value<0 for value in (low_space_bytes,growth_bytes,duplicate_bytes)):
        raise ValueError('advisory thresholds must be nonnegative integer bytes')
    warnings=[]
    for volume in report.get('volumes',[]):
        free=volume.get('free_bytes')
        if type(free)is int and free<low_space_bytes:
            warnings.append(dict(kind='LOW_VOLUME_SPACE',volume=volume.get('volume'),observed_bytes=free,threshold_bytes=low_space_bytes,action='review before new large evidence; advisory only'))
    duplicate=report.get("content_duplicates",{});duplicate_total=sum(x.get("allocated_bytes_known_unique_observed",0) for x in duplicate.get("groups",[]))
    if duplicate.get("status")=="COMPLETE" and duplicate_total>duplicate_bytes:
        warnings.append(dict(kind="DUPLICATE_CONTENT_REVIEW",observed_bytes=duplicate_total,threshold_bytes=duplicate_bytes,action="review independent SHA-matched identities; allocation is not reclaimable bytes"))
    growth=report.get('growth',{});delta=growth.get('allocated_delta_bytes')
    if growth.get('status')=='COMPARABLE' and type(delta)is int and delta>growth_bytes:
        warnings.append(dict(kind='PROJECT_GROWTH_SINCE_PREVIOUS_INVENTORY',observed_bytes=delta,threshold_bytes=growth_bytes,action='review large observed categories; advisory only'))
    return dict(low_space_bytes=low_space_bytes,growth_bytes=growth_bytes,duplicate_bytes=duplicate_bytes,warnings=warnings,automatically_deletes=False,enforces_generation_limit=False)


def _ancestor_reparse(path):
    chain=[str(parent) for parent in reversed(Path(path).parents)]+[path]
    for candidate in chain:
        metadata=os.lstat(candidate)
        if is_link(metadata):return candidate,metadata
    return None


def _stable_content_sha256(path, expected):
    """Stream one identity with a no-follow read handle; refuse changes or sharing conflicts.

    The name/ancestor checks are observations, not an atomic guarantee against
    hostile concurrent namespace changes. Nothing here authorizes removal.
    """
    if _ancestor_reparse(path) is not None:raise RuntimeError("content path has reparse ancestor")
    def signature(info):
        return (file_identity(info),info.st_size,getattr(info,"st_mtime_ns",None),getattr(info,"st_nlink",None))
    before=os.lstat(path)
    required=(tuple(expected["file_identity"]),expected["logical_bytes"],expected["mtime_ns"],expected["reported_nlink"])
    if is_link(before) or not stat.S_ISREG(before.st_mode) or signature(before)!=required:
        raise RuntimeError("identity or metadata changed since inventory")
    if os.name=="nt":
        import msvcrt
        kernel=_allocation_api()
        # Read-only, deny concurrent writes/deletes, open the final reparse object
        # rather than following it. The tag check precedes reading any bytes.
        handle=kernel.CreateFileW(path,0x80000000,1,None,3,0x00200000|0x08000000,None)
        if handle in (None,0,ctypes.c_void_p(-1).value):raise OSError(kernel.GetLastError(),"content read handle unavailable",path)
        try:
            tag=_FileAttributeTagInfo()
            if not kernel.GetFileInformationByHandleEx(handle,9,ctypes.byref(tag),ctypes.sizeof(tag)):
                raise OSError(kernel.GetLastError(),"content FileAttributeTagInfo unavailable",path)
            if tag.FileAttributes&REPARSE_POINT or tag.ReparseTag:raise RuntimeError("content handle is reparse")
            fd=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
        except BaseException:
            kernel.CloseHandle(handle);raise
    else:
        fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    try:stream=os.fdopen(fd,"rb")
    except BaseException:
        os.close(fd);raise
    with stream:
        if signature(os.fstat(stream.fileno()))!=required:raise RuntimeError("opened content identity differs")
        digest=hashlib.sha256()
        for block in iter(lambda:stream.read(1024*1024),b""):digest.update(block)
        if signature(os.fstat(stream.fileno()))!=required:raise RuntimeError("content changed while hashing")
    if _ancestor_reparse(path) is not None or signature(os.lstat(path))!=required:
        raise RuntimeError("content path changed after hashing")
    return digest.hexdigest()


def content_duplicate_report(groups,suffixes,*,inventory_errors=0):
    """Opt-in same-length SHA groups by actual file identity, never a deletion plan."""
    if not isinstance(suffixes,(list,tuple,set)) or any(type(x)is not str or not x.startswith(".") or len(x)<2 or any(c in x for c in "/\\") for x in suffixes):
        raise ValueError("duplicate suffixes must be simple extensions such as .mix")
    wanted={x.casefold() for x in suffixes}
    if not wanted:return dict(status="DISABLED",suffixes=[],groups=[],errors=[],deletion_authorized=False)
    buckets=defaultdict(list);errors=[]
    for group in groups:
        if not any(Path(name).suffix.casefold() in wanted for name in group["aliases"]):continue
        if group["file_identity"] is None or type(group["reported_nlink"]) is not int or group["reported_nlink"]<1 or type(group["mtime_ns"]) is not int:
            errors.append(dict(path=group["representative"],error="file identity, link count or modification time unavailable"));continue
        buckets[group["logical_bytes"]].append(group)
    grouped=defaultdict(list);hashed=0
    for size,items in buckets.items():
        if len(items)<2:continue # hardlink aliases are one identity; size alone is not proof.
        for group in items:
            try:
                digest=_stable_content_sha256(group["representative"],group);hashed+=1
                grouped[(size,digest)].append(group)
            except (OSError,RuntimeError,ValueError) as exc:
                errors.append(dict(path=group["representative"],error=type(exc).__name__+": "+str(exc)))
    matches=[]
    for (size,digest),items in grouped.items():
        if len(items)<2:continue
        unknown=sum(item["allocated_bytes"] is None for item in items)
        matches.append(dict(sha256=digest,logical_bytes_each=size,independent_file_identities=len(items),
            observed_alias_paths=sum(len(item["aliases"]) for item in items),
            allocated_bytes_known_unique_observed=sum(item["allocated_bytes"] or 0 for item in items),
            allocated_unknown_identities=unknown,
            identities=[dict(path=item["representative"],file_identity=item["file_identity"],
                observed_aliases=len(item["aliases"]),reported_nlink=item["reported_nlink"],
                external_links_possible=(item["reported_nlink"] or 0)>len(item["aliases"]),
                allocated_bytes=item["allocated_bytes"],protected_reasons=item["protected_reasons"]) for item in items],
            estimated_reclaimable_bytes=None,deletion_authorized=False))
    return dict(status="PARTIAL" if errors or inventory_errors else "COMPLETE",suffixes=sorted(wanted),
        identities_hashed=hashed,groups=sorted(matches,key=lambda item:-item["allocated_bytes_known_unique_observed"]),
        errors=errors,inventory_errors=inventory_errors,deletion_authorized=False,
        scope="Repeated sizes among traversed files only; hashing once per identity. Allocation is not reclaimable bytes.")


def audit(roots,*,allowed_roots=None,keep_paths=(),repo_paths=(),allocation_reader=None,hash_duplicate_suffixes=()):
    """Inventory only explicit allowlisted roots; never resolve/follow links."""
    started=time.monotonic();started_utc=datetime.now(timezone.utc).isoformat()
    roots=list(dict.fromkeys(absolute(path) for path in roots))
    if not roots:raise ValueError("at least one explicit root is required")
    allowed=[absolute(path) for path in (roots if allowed_roots is None else allowed_roots)]
    if not allowed or any(not any(within(root,entry) for entry in allowed) for root in roots):
        raise ValueError("requested root is outside the explicit path allowlist")
    keeps=[absolute(path) for path in keep_paths];repos=[absolute(path) for path in repo_paths]
    if any(not any(within(repo,root) for root in roots) for repo in repos):raise ValueError("repo label is outside explicit audit roots")
    reader=allocated_size if allocation_reader is None else allocation_reader
    errors=[];links=[];directories=[];groups={};top=[];counter=0;unknown_identity=0
    extensions=defaultdict(lambda:dict(file_paths=0,logical_bytes_by_path=0,allocated_bytes_known_by_path=0,allocated_unknown_paths=0))

    def error(path,operation,exc):
        errors.append(dict(path=path,operation=operation,error_type=type(exc).__name__,error=str(exc)))

    def inventory_link(path,metadata,*,requested_root=None):
        try:target=os.readlink(path)
        except OSError as exc:target=None;error(path,"readlink_metadata",exc)
        links.append(dict(path=path,target_text=target,reparse_tag=getattr(metadata,"st_reparse_tag",None),
                          attributes=getattr(metadata,"st_file_attributes",None),requested_root=requested_root,
                          traversed=False,target_bytes_included=False,estimated_reclaimable_bytes=None))

    def file_record(path,metadata):
        nonlocal counter,unknown_identity
        identity=file_identity(metadata);allocated=None
        try:
            allocated=reader(path)
            if allocated is not None and (type(allocated) is not int or allocated<0):raise ValueError("invalid allocated-size result")
            after=os.lstat(path)
            if is_link(after) or not stat.S_ISREG(after.st_mode) or file_identity(after)!=identity or after.st_size!=metadata.st_size:
                raise RuntimeError("file metadata changed during allocation observation")
        except (OSError,RuntimeError,ValueError) as exc:allocated=None;error(path,"allocated_size",exc)
        key=identity
        if key is None:unknown_identity+=1;key=("unavailable",path)
        record=dict(path=path,logical_bytes=metadata.st_size,allocated_bytes=allocated,
                    file_identity=list(identity) if identity is not None else None,nlink=getattr(metadata,"st_nlink",None),
                    protected_reasons=protection(path,keep_paths=keeps),category=classify(path),
                    attributes=getattr(metadata,"st_file_attributes",None),
                    sparse=(bool(metadata.st_file_attributes&SPARSE_FILE) if type(getattr(metadata,"st_file_attributes",None)) is int else None),
                    compressed=(bool(metadata.st_file_attributes&COMPRESSED_FILE) if type(getattr(metadata,"st_file_attributes",None)) is int else None))
        group=groups.get(key)
        if group is None:
            groups[key]=dict(representative=path,logical_bytes=metadata.st_size,allocated_bytes=allocated,
                             file_identity=record["file_identity"],reported_nlink=record["nlink"],aliases=[path],protected_reasons=record["protected_reasons"],
                             sparse=record["sparse"],compressed=record["compressed"],mtime_ns=getattr(metadata,"st_mtime_ns",None))
        else:
            group["aliases"].append(path)
            group["protected_reasons"]=sorted(set(group["protected_reasons"])|set(record["protected_reasons"]))
            if group["logical_bytes"]!=metadata.st_size or (allocated is not None and group["allocated_bytes"] is not None and allocated!=group["allocated_bytes"]):
                error(path,"identity_observation",RuntimeError("shared file identity changed sizes during scan"))
            if group["allocated_bytes"] is None and allocated is not None:group["allocated_bytes"]=allocated
            if record["nlink"] is not None:group["reported_nlink"]=max(group["reported_nlink"] or 0,record["nlink"])
        ext=Path(path).suffix.casefold() or "[no extension]";item=extensions[ext]
        item["file_paths"]+=1;item["logical_bytes_by_path"]+=metadata.st_size
        if allocated is None:item["allocated_unknown_paths"]+=1
        else:item["allocated_bytes_known_by_path"]+=allocated
        counter+=1;heapq.heappush(top,(metadata.st_size,counter,record))
        if len(top)>50:heapq.heappop(top)
        return key,allocated

    def directory(path,root,depth):
        info=dict(path=path,root=root,depth=depth,direct_files=0,direct_directories=0,direct_links=0,
                  file_paths=0,descendant_directories=0,link_entries=0,logical_bytes_by_path=0,
                  allocated_bytes_known_by_path=0,allocated_unknown_paths=0,other_entries=0)
        identities=set()
        try:
            before=os.lstat(path)
            if is_link(before):inventory_link(path,before);info["direct_links"]=info["link_entries"]=1;return info,identities
            if not stat.S_ISDIR(before.st_mode):raise ValueError("directory changed type")
            with os.scandir(path) as entries:
                for entry in entries:
                    child=os.path.join(path,entry.name)
                    if not any(within(child,allow) for allow in allowed):
                        error(child,"allowlist",ValueError("entry escaped explicit allowlist"));continue
                    try:metadata=os.lstat(child)
                    except OSError as exc:error(child,"lstat",exc);continue
                    if is_link(metadata):
                        inventory_link(child,metadata);info["direct_links"]+=1;info["link_entries"]+=1
                    elif stat.S_ISREG(metadata.st_mode):
                        key,allocated=file_record(child,metadata);identities.add(key)
                        info["direct_files"]+=1;info["file_paths"]+=1;info["logical_bytes_by_path"]+=metadata.st_size
                        if allocated is None:info["allocated_unknown_paths"]+=1
                        else:info["allocated_bytes_known_by_path"]+=allocated
                    elif stat.S_ISDIR(metadata.st_mode):
                        info["direct_directories"]+=1
                        nested,nested_ids=directory(child,root,depth+1)
                        for name in ("file_paths","link_entries","logical_bytes_by_path","allocated_bytes_known_by_path","allocated_unknown_paths","other_entries"):
                            info[name]+=nested[name]
                        info["descendant_directories"]+=1+nested["descendant_directories"]
                        if len(nested_ids)>len(identities):identities,nested_ids=nested_ids,identities
                        identities.update(nested_ids)
                    else:info["other_entries"]+=1
            after=os.lstat(path)
            if is_link(after) or file_identity(after)!=file_identity(before):raise RuntimeError("directory changed identity during scan")
        except (OSError,ValueError,RuntimeError,RecursionError) as exc:error(path,"scandir",exc)
        info["unique_observed_file_identities"]=len(identities)
        info["logical_bytes_unique_observed"]=sum(groups[key]["logical_bytes"] for key in identities)
        info["allocated_bytes_known_unique_observed"]=sum(groups[key]["allocated_bytes"] or 0 for key in identities)
        info["allocated_unknown_unique_observed"]=sum(groups[key]["allocated_bytes"] is None for key in identities)
        info["protected_reasons"]=protection(path,keep_paths=keeps)
        info["contains_explicit_keep"]=any(within(keep,path) for keep in keeps)
        directories.append(info)
        return info,identities

    root_results=[];covered=[]
    for root in sorted(roots,key=lambda path:(len(Path(path).parts),os.path.normcase(path))):
        previous=next((entry for entry in covered if within(root,entry)),None)
        if previous is not None:root_results.append(dict(path=root,status="covered_by_outer_explicit_root",covered_by=previous));continue
        try:
            blocked=_ancestor_reparse(root)
            if blocked is not None:
                inventory_link(*blocked,requested_root=root)
                root_results.append(dict(path=root,status="reparse_root_or_ancestor_not_traversed"));continue
            metadata=os.lstat(root)
            if not stat.S_ISDIR(metadata.st_mode):raise ValueError("audit root must be a real directory")
            result,_=directory(root,root,0);root_results.append(dict(path=root,status="scanned",totals=result));covered.append(root)
        except (OSError,ValueError) as exc:error(root,"root",exc);root_results.append(dict(path=root,status="unavailable"))
    allocated_known=sum(group["allocated_bytes"] or 0 for group in groups.values())
    hardlinks=[]
    for group in groups.values():
        if len(group["aliases"])>1 or (group["reported_nlink"] or 0)>1:
            value=dict(group);value["observed_aliases"]=len(value["aliases"])
            value["external_links_possible"]=(value["reported_nlink"] or 0)>value["observed_aliases"]
            value["estimated_reclaimable_bytes"]=None;value["deletion_authorized"]=False
            hardlinks.append(value)
    unique_files=[];categories=defaultdict(lambda:dict(unique_observed_file_identities=0,logical_bytes_unique_observed=0,allocated_bytes_known_unique_observed=0,allocated_unknown_unique_observed=0));size_counts=defaultdict(int)
    unique_extensions=defaultdict(lambda:dict(unique_observed_file_identities=0,logical_bytes_unique_observed=0,
                            allocated_bytes_known_unique_observed=0,allocated_unknown_unique_observed=0))
    for group in groups.values():
        classes=sorted({classify(path) for path in group["aliases"]});category=classes[0] if len(classes)==1 else "mixed_path_categories_review"
        category_row=categories[category];category_row["unique_observed_file_identities"]+=1
        category_row["logical_bytes_unique_observed"]+=group["logical_bytes"]
        if group["allocated_bytes"] is None:category_row["allocated_unknown_unique_observed"]+=1
        else:category_row["allocated_bytes_known_unique_observed"]+=group["allocated_bytes"]
        size_counts[group["logical_bytes"]]+=1
        suffixes=sorted({Path(path).suffix.casefold() or "[no extension]" for path in group["aliases"]})
        extension=suffixes[0] if len(suffixes)==1 else "[mixed suffixes]"
        item=unique_extensions[extension];item["unique_observed_file_identities"]+=1
        item["logical_bytes_unique_observed"]+=group["logical_bytes"]
        if group["allocated_bytes"] is None:item["allocated_unknown_unique_observed"]+=1
        else:item["allocated_bytes_known_unique_observed"]+=group["allocated_bytes"]
        unique_files.append(dict(group,observed_aliases=len(group["aliases"]),extensions=suffixes,
                                 external_links_possible=(group["reported_nlink"] or 0)>len(group["aliases"]),estimated_reclaimable_bytes=None))
    directory_by_path={os.path.normcase(item["path"]):item for item in directories}
    repo_results=[dict(path=repo,totals=directory_by_path.get(os.path.normcase(repo)),scanned=os.path.normcase(repo) in directory_by_path) for repo in repos]
    disks=[]
    for anchor in sorted({Path(root).anchor for root in roots}):
        try:
            usage=shutil.disk_usage(anchor);disks.append(dict(volume=anchor,total_bytes=usage.total,used_bytes=usage.used,free_bytes=usage.free,
                                                            scope="volume background metadata, not reclaimable bytes"))
        except OSError as exc:error(anchor,"disk_usage",exc)
    top_files=[item[2] for item in sorted(top,key=lambda item:(-item[0],item[2]["path"]))]
    review=[dict(path=item["path"],logical_bytes=item["logical_bytes"],action="review_only",deletion_authorized=False,
                 estimated_reclaimable_bytes=None,reason="derived artifact; dependencies, preservation and all hard links require separate review")
            for item in top_files if Path(item["path"]).suffix.casefold() in DERIVED_SUFFIXES and not item["protected_reasons"] and
            not groups[tuple(item["file_identity"]) if item["file_identity"] is not None else ("unavailable",item["path"])]["protected_reasons"]]
    totals=dict(file_paths=counter,unique_observed_file_identities=len(groups),hardlink_identity_unavailable_paths=unknown_identity,
                logical_bytes_by_path=sum(item["totals"]["logical_bytes_by_path"] for item in root_results if item.get("totals")),
                logical_bytes_unique_observed=sum(group["logical_bytes"] for group in groups.values()),
                allocated_bytes_known_unique_observed=allocated_known,
                allocated_unknown_unique_observed=sum(group["allocated_bytes"] is None for group in groups.values()),
                directories=len(directories),link_entries=len(links),errors=len(errors),
                hardlink_groups=len(hardlinks),hardlink_groups_with_external_links=sum(item["external_links_possible"] for item in hardlinks),
                observed_aliases_in_hardlink_groups=sum(item["observed_aliases"] for item in hardlinks),
                estimated_reclaimable_bytes=None)
    report=dict(schema="yr-storage-audit-v1",mode="dry-run-read-only",started_utc=started_utc,finished_utc=datetime.now(timezone.utc).isoformat(),
                tool_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                elapsed_seconds=round(time.monotonic()-started,3),requested_roots=roots,allowed_roots=allowed,explicit_keep_paths=keeps,
                totals=totals,workspace_roots=root_results,repo_roots=repo_results,directories=directories,
                top20_directories=sorted(directories,key=lambda item:(-item["logical_bytes_by_path"],item["path"]))[:20],
                top30_directories=sorted(directories,key=lambda item:(-item["allocated_bytes_known_unique_observed"],item["path"]))[:30],
                top30_files=top_files[:30],top50_files=top_files,top30_unique_files=sorted(unique_files,key=lambda item:(-item["logical_bytes"],item["representative"]))[:30],
                top50_unique_files=sorted(unique_files,key=lambda item:(-(item["allocated_bytes"] or 0),-item["logical_bytes"],item["representative"]))[:50],
                categories_unique_observed=sorted([dict(category=category,**value)for category,value in categories.items()],key=lambda item:-item["allocated_bytes_known_unique_observed"]),
                size_collision_groups=sorted([dict(logical_bytes=size,distinct_file_identities=count,content_equal=None)for size,count in size_counts.items()if count>1],key=lambda item:-item["logical_bytes"])[:50],
                storage_attributes=dict(sparse_unique=sum(g["sparse"] is True for g in groups.values()),compressed_unique=sum(g["compressed"] is True for g in groups.values()),attribute_unknown_unique=sum(g["sparse"] is None or g["compressed"] is None for g in groups.values())),
                growth=dict(status="UNKNOWN",logical_delta_bytes=None,allocated_delta_bytes=None,reason="no prior comparable inventory supplied"),
                extensions_unique_observed=sorted([dict(extension=ext,**value) for ext,value in unique_extensions.items()],key=lambda item:-item["logical_bytes_unique_observed"]),
                unique_extension_rule="Each observed file identity counted once; aliases with differing suffixes use [mixed suffixes].",
                extensions=sorted([dict(extension=ext,**value) for ext,value in extensions.items()],key=lambda item:-item["logical_bytes_by_path"]),
                hardlink_groups=sorted(hardlinks,key=lambda item:-item["logical_bytes"]),links=links,errors=errors,volumes=disks,
                review_plan=review,deletion_authorized=False,logical_inventory_complete=not errors,
                allocated_size_method="GetFileInformationByHandleEx(FileStandardInfo).AllocationSize; OPEN_REPARSE_POINT and tag-checked handle" if os.name=="nt" and allocation_reader is None else "unavailable or caller-supplied metadata provider",
                limitations=["Reparse and symlink targets are never intentionally traversed; links are separate metadata only.",
                             "Logical lengths are not disk allocation or deletion savings; allocated metadata is not exclusive extents.",
                             "Windows allocation uses FileStandardInfo.AllocationSize through a tag-checked OPEN_REPARSE_POINT handle; failures remain unknown.",
                             "Directory aggregates overlap and must not be added together as physical volume usage.",
                             "By default contents are not hashed. Optional SHA groups never prove block deduplication or deletability.",
                             "Hardlink identity dedup covers observed paths only; external links and metadata changes can prevent complete accounting.",
                             "No deletion plan or reclaimable-byte estimate is authorized; even all observed nlinks do not prove exclusive volume extents.",
                             "This live metadata inventory is not an atomic filesystem snapshot.",
                             "Metadata inventory does not load contents; optional duplicate hashing streams bytes. Identity and alias summaries consume memory proportional to observed file count."])
    report['content_duplicates']=content_duplicate_report(groups.values(),hash_duplicate_suffixes,inventory_errors=len(errors))
    report['advisories']=recommendations(report)
    return report


def markdown(report):
    totals=report["totals"]
    lines=["# Read-only storage inventory","",f"Mode: {report['mode']}. No deletion is authorized.","",
           f"Logical bytes by path: {totals['logical_bytes_by_path']:,}; unique observed identities: {totals['logical_bytes_unique_observed']:,} logical bytes.",
           f"Known allocated bytes, observed identities deduplicated: {totals['allocated_bytes_known_unique_observed']:,}; unknown identities: {totals['allocated_unknown_unique_observed']}.",
           f"Links: {totals['link_entries']}; errors: {totals['errors']}. Reclaimable bytes: UNKNOWN.","",
           "Logical and allocated values below are inventory observations, not deletion savings.","","## Workspace and repository totals",""]
    for group in (report["workspace_roots"],report["repo_roots"]):
        for item in group:
            value=item.get("totals")
            lines.append(f"- {item['path']}: {value['logical_bytes_by_path']:,} logical bytes by path" if value else f"- {item['path']}: not separately traversed / unavailable")
    lines.extend(["","## Top 30 directories by known unique allocation","","| Directory | Logical bytes by path | Known unique allocated bytes | Unknown allocation identities |","| --- | ---: | ---: | ---: |"])
    for item in report["top30_directories"]:lines.append(f"| {item['path'].replace('|','%7C')} | {item['logical_bytes_by_path']} | {item['allocated_bytes_known_unique_observed']} | {item['allocated_unknown_unique_observed']} |")
    lines.extend(["","## Top 50 files by logical length","","| File | Logical bytes | Allocated bytes | Protection |","| --- | ---: | ---: | --- |"])
    for item in report["top50_files"]:lines.append(f"| {item['path'].replace('|','%7C')} | {item['logical_bytes']} | {item['allocated_bytes']} | {', '.join(item['protected_reasons'])} |")
    lines.extend(["","## Path categories (unique observed identities)","","Classification indicates path and file type, not deletion eligibility or current identity.","","| Category | Logical bytes | Known allocation | Unknown allocation |","| --- | ---: | ---: | ---: |"])
    for item in report['categories_unique_observed']:lines.append(f"| {item['category']} | {item['logical_bytes_unique_observed']} | {item['allocated_bytes_known_unique_observed']} | {item['allocated_unknown_unique_observed']} |")
    lines.extend(["","## Growth and attributes","",f"Growth: {report['growth']['status']}; logical delta: {report['growth']['logical_delta_bytes']}; allocation delta: {report['growth']['allocated_delta_bytes']}; {report['growth']['reason']}.",f"Sparse / compressed / attribute unknown observed identities: {report['storage_attributes']['sparse_unique']} / {report['storage_attributes']['compressed_unique']} / {report['storage_attributes']['attribute_unknown_unique']}.","Size collisions are candidates only: matching length never proves duplicate content."])
    lines.extend(["","## Top 30 unique observed files","","| Representative | Logical bytes | Allocated bytes | Observed aliases / nlink |","| --- | ---: | ---: | ---: |"])
    for item in report["top30_unique_files"]:lines.append(f"| {item['representative'].replace('|','%7C')} | {item['logical_bytes']} | {item['allocated_bytes']} | {item['observed_aliases']} / {item['reported_nlink']} |")
    lines.extend(["","## Unique observed extension groups","",report["unique_extension_rule"],"","| Extension | Unique logical bytes | Known allocated bytes | Unknown allocation identities |","| --- | ---: | ---: | ---: |"])
    for item in report["extensions_unique_observed"]:lines.append(f"| {item['extension']} | {item['logical_bytes_unique_observed']} | {item['allocated_bytes_known_unique_observed']} | {item['allocated_unknown_unique_observed']} |")
    lines.extend(["","## Content duplicate SHA review","",f"Status: {report.get('content_duplicates',{}).get('status','DISABLED')}; independent equal-content groups: {len(report.get('content_duplicates',{}).get('groups',[]))}. These are not deletion candidates or guaranteed savings."])
    for group in report.get("content_duplicates",{}).get("groups",[]):lines.append(f"- SHA {group['sha256']}: {group['independent_file_identities']} independent identities, {group['allocated_bytes_known_unique_observed']} observed allocated bytes.")
    lines.extend(["","## Advisory alerts","",f"Low space threshold: {report['advisories']['low_space_bytes']} bytes; single-interval growth threshold: {report['advisories']['growth_bytes']} bytes; duplicate-content allocation threshold: {report['advisories']['duplicate_bytes']} bytes. These alerts do not enforce test-output limits."])
    for warning in report['advisories']['warnings']:lines.append(f"- {warning['kind']}: observed {warning['observed_bytes']} bytes; {warning['action']}.")
    lines.extend(["","## Review only","","No path is marked deletable. Current hosts, Git metadata, environments, game resources and explicit keep paths stay protected."])
    for item in report["review_plan"]:lines.append(f"- {item['path']}: review derived-artifact dependencies and preservation separately; no removal or byte-saving claim.")
    lines.extend(["","## Limitations",""]+[f"- {text}" for text in report["limitations"]])
    return "\n".join(lines)+"\n"


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",action="append",required=True)
    parser.add_argument("--allow",action="append",help="Explicit lexical path allowlist; defaults to the supplied roots")
    parser.add_argument("--keep",action="append",default=[])
    parser.add_argument("--repo",action="append",default=[])
    parser.add_argument("--previous",type=Path,help="Optional earlier inventory.json for same-root growth comparison")
    parser.add_argument("--hash-duplicates",action="append",default=[],metavar=".EXT",help="Opt-in full SHA-256 of same-size independent identities for this extension; default reads no content")
    parser.add_argument("--low-space-gib",type=int,default=20,help="Advisory volume low-water mark in GiB; default 20")
    parser.add_argument("--growth-gib",type=int,default=10,help="Advisory one-interval allocation growth in GiB; default 10")
    parser.add_argument("--duplicate-warning-gib",type=int,default=10,help="Advisory threshold for SHA-matched independent-identity allocation in GiB; default 10")
    parser.add_argument("--out-dir",type=Path,help="New private output directory; existing directories are refused")
    args=parser.parse_args(argv)
    if args.out_dir is not None and args.out_dir.exists():parser.error("output directory must not already exist")
    previous=None
    if args.previous is not None:
        with args.previous.open("r",encoding="utf-8") as stream:previous=json.load(stream)
    report=audit(args.root,allowed_roots=args.allow,keep_paths=args.keep,repo_paths=args.repo,hash_duplicate_suffixes=args.hash_duplicates)
    if args.previous is not None:report["growth"]=growth_comparison(previous,report)
    if args.low_space_gib<0 or args.growth_gib<0 or args.duplicate_warning_gib<0:parser.error("advisory GiB thresholds must be nonnegative")
    report["advisories"]=recommendations(report,low_space_bytes=args.low_space_gib*1024**3,growth_bytes=args.growth_gib*1024**3,duplicate_bytes=args.duplicate_warning_gib*1024**3)
    if args.out_dir is None:print(json.dumps(report,indent=2,ensure_ascii=False))
    else:
        args.out_dir.mkdir(parents=False,exist_ok=False)
        with (args.out_dir/"inventory.json").open("x",encoding="utf-8") as stream:json.dump(report,stream,indent=2,ensure_ascii=False)
        with (args.out_dir/"inventory.md").open("x",encoding="utf-8") as stream:stream.write(markdown(report))
        print(json.dumps(dict(output=str(args.out_dir.absolute()),totals=report["totals"],volumes=report["volumes"]),ensure_ascii=False))
    return 0


if __name__=="__main__":raise SystemExit(main())
