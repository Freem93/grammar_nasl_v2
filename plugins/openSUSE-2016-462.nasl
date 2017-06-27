#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-462.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90558);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2014-8143", "CVE-2015-0240", "CVE-2015-3223", "CVE-2015-5252", "CVE-2015-5296", "CVE-2015-5299", "CVE-2015-5330", "CVE-2015-5370", "CVE-2015-7560", "CVE-2015-8467", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2115", "CVE-2016-2118");

  script_name(english:"openSUSE Security Update : samba (openSUSE-2016-462) (Badlock)");
  script_summary(english:"Check for the openSUSE-2016-462 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"samba was updated to version 4.2.4 to fix 14 security issues.

These security issues were fixed :

  - CVE-2015-5370: DCERPC server and client were vulnerable
    to DOS and MITM attacks (bsc#936862).

  - CVE-2016-2110: A man-in-the-middle could have downgraded
    NTLMSSP authentication (bsc#973031).

  - CVE-2016-2111: Domain controller netlogon member
    computer could have been spoofed (bsc#973032).

  - CVE-2016-2112: LDAP conenctions were vulnerable to
    downgrade and MITM attack (bsc#973033).

  - CVE-2016-2113: TLS certificate validation were missing
    (bsc#973034).

  - CVE-2016-2115: Named pipe IPC were vulnerable to MITM
    attacks (bsc#973036).

  - CVE-2016-2118: 'Badlock' DCERPC impersonation of
    authenticated account were possible (bsc#971965).

  - CVE-2015-3223: Malicious request can cause Samba LDAP
    server to hang, spinning using CPU (boo#958581).

  - CVE-2015-5330: Remote read memory exploit in LDB
    (boo#958586).

  - CVE-2015-5252: Insufficient symlink verification (file
    access outside the share)(boo#958582).

  - CVE-2015-5296: No man in the middle protection when
    forcing smb encryption on the client side (boo#958584).

  - CVE-2015-5299: Currently the snapshot browsing is not
    secure thru windows previous version (shadow_copy2)
    (boo#958583).

  - CVE-2015-8467: Fix Microsoft MS15-096 to prevent machine
    accounts from being changed into user accounts
    (boo#958585).

  - CVE-2015-7560: Getting and setting Windows ACLs on
    symlinks can change permissions on link target
    (boo#968222).

These non-security issues were fixed :

  - Fix samba.tests.messaging test and prevent potential tdb
    corruption by removing obsolete now invalid tdb_close
    call; (boo#974629).

  - Align fsrvp feature sources with upstream version.

  - Obsolete libsmbsharemodes0 from samba-libs and
    libsmbsharemodes-devel from samba-core-devel;
    (boo#973832).

  - s3:utils/smbget: Fix recursive download; (bso#6482).

  - s3: smbd: posix_acls: Fix check for setting u:g:o entry
    on a filesystem with no ACL support; (bso#10489).

  - docs: Add example for domain logins to smbspool man
    page; (bso#11643).

  - s3-client: Add a KRB5 wrapper for smbspool; (bso#11690).

  - loadparm: Fix memory leak issue; (bso#11708).

  - lib/tsocket: Work around sockets not supporting
    FIONREAD; (bso#11714).

  - ctdb-scripts: Drop use of 'smbcontrol winbindd
    ip-dropped ...'; (bso#11719).

  - s3:smbd:open: Skip redundant call to file_set_dosmode
    when creating a new file; (bso#11727).

  - param: Fix str_list_v3 to accept ';' again; (bso#11732).

  - Real memeory leak(buildup) issue in loadparm;
    (bso#11740).

  - Obsolete libsmbclient from libsmbclient0 and
    libpdb-devel from libsamba-passdb-devel while not
    providing it; (boo#972197).

  - Upgrade on-disk FSRVP server state to new version;
    (boo#924519).

  - Only obsolete but do not provide gplv2/3 package names;
    (boo#968973).

  - Enable clustering (CTDB) support; (boo#966271).

  - s3: smbd: Fix timestamp rounding inside SMB2 create;
    (bso#11703); (boo#964023).

  - vfs_fruit: Fix renaming directories with open files;
    (bso#11065).

  - Fix MacOS finder error 36 when copying folder to Samba;
    (bso#11347).

  - s3:smbd/oplock: Obey kernel oplock setting when
    releasing oplocks; (bso#11400).

  - Fix copying files with vfs_fruit when using
    vfs_streams_xattr without stream prefix and type suffix;
    (bso#11466).

  - s3:libsmb: Correctly initialize the list head when
    keeping a list of primary followed by DFS connections;
    (bso#11624).

  - Reduce the memory footprint of empty string options;
    (bso#11625).

  - lib/async_req: Do not install async_connect_send_test;
    (bso#11639).

  - docs: Fix typos in man vfs_gpfs; (bso#11641).

  - smbd: make 'hide dot files' option work with 'store dos
    attributes = yes'; (bso#11645).

  - smbcacls: Fix uninitialized variable; (bso#11682).

  - s3:smbd: Ignore initial allocation size for directory
    creation; (bso#11684).

  - Changing log level of two entries to from 1 to 3;
    (bso#9912).

  - vfs_gpfs: Re-enable share modes; (bso#11243).

  - wafsamba: Also build libraries with RELRO protection;
    (bso#11346).

  - ctdb: Strip trailing spaces from nodes file;
    (bso#11365).

  - s3-smbd: Fix old DOS client doing wildcard delete -
    gives a attribute type of zero; (bso#11452).

  - nss_wins: Do not run into use after free issues when we
    access memory allocated on the globals and the global
    being reinitialized; (bso#11563).

  - async_req: Fix non-blocking connect(); (bso#11564).

  - auth: gensec: Fix a memory leak; (bso#11565).

  - lib: util: Make non-critical message a warning;
    (bso#11566).

  - Fix winbindd crashes with samlogon for trusted domain
    user; (bso#11569); (boo#949022).

  - smbd: Send SMB2 oplock breaks unencrypted; (bso#11570).

  - ctdb: Open the RO tracking db with perms 0600 instead of
    0000; (bso#11577).

  - manpage: Correct small typo error; (bso#11584).

  - s3: smbd: If EA's are turned off on a share don't allow
    an SMB2 create containing them; (bso#11589).

  - Backport some valgrind fixes from upstream master;
    (bso#11597).

  - s3: smbd: have_file_open_below() fails to enumerate open
    files below an open directory handle; (bso#11615).

  - docs: Fix some typos in the idmap config section of man
    5 smb.conf; (bso#11619).

  - Remove redundant configure options while adding
    with-relro.

  - s3: smbd: Fix our access-based enumeration on 'hide
    unreadable' to match Windows; (bso#10252).

  - smbd: Fix file name buflen and padding in notify
    repsonse; (bso#10634).

  - kerberos: Make sure we only use prompter type when
    available; (bso#11038).

  - s3:ctdbd_conn: Make sure we destroy tevent_fd before
    closing the socket; (bso#11316).

  - dcerpc.idl: accept invalid dcerpc_bind_nak pdus;
    (bso#11327).

  - Fix a deadlock in tdb; (bso#11381).

  - s3: smbd: Fix mkdir race condition; (bso#11486).

  - pam_winbind: Fix a segfault if initialization fails;
    (bso#11502).

  - s3: dfs: Fix a crash when the dfs targets are disabled;
    (bso#11509).

  - s3: smbd: Fix opening/creating :stream files on the root
    share directory; (bso#11522).

  - net: Fix a crash with 'net ads keytab create';
    (bso#11528).

  - s3: smbd: Fix a crash in unix_convert() and a NULL
    pointer bug introduced by previous 'raw' stream fix
    (bso#11522); (bso#11535).

  - vfs_fruit: Return value of ad_pack in vfs_fruit.c;
    (bso#11543).

  - vfs_commit: Set the fd on open before calling
    SMB_VFS_FSTAT; (bso#11547).

  - Fix bug in smbstatus where the lease info is not
    printed; (bso#11549).

  - s3:smbstatus: Add stream name to share_entry_forall();
    (bso#11550).

  - Relocate the tmpfiles.d directory to the client package;
    (boo#947552).

  - Do not provide libpdb0 from libsamba-passdb0 but add it
    to baselibs.conf instead; (boo#942716).

  - Package /var/lib/samba/private/sock with 0700
    permissions; (boo#946051).

  - auth/credentials: If credentials have principal set,
    they are not anonymous anymore; (bso#11265).

  - Fix stream names with colon with 'fruit:encoding =
    native'; (bso#11278).

  - s4:rpc_server/netlogon: Fix for NetApp; (bso#11291).

  - lib: Fix rundown of open_socket_out(); (bso#11316).

  - s3:lib: Fix some corner cases of
    open_socket_out_cleanup(); (bso#11316).

  - vfs:fruit: Implement copyfile style copy_chunk;
    (bso#11317).

  - ctdb-daemon: Return correct sequence number for
    CONTROL_GET_DB_SEQNUM; (bso#11398).

  - ctdb-scripts: Support monitoring of interestingly named
    VLANs on bonds; (bso#11399).

  - ctdb-daemon: Improve error handling for running event
    scripts; (bso#11431).

  - ctdb-daemon: Check if updates are in flight when
    releasing all IPs; (bso#11432).

  - ctdb-build: Fix building of PCP PMDA module;
    (bso#11435).

  - Backport dcesrv_netr_DsRGetDCNameEx2 fixes; (bso#11454).

  - vfs_fruit: Handling of empty resource fork; (bso#11467).

  - Avoid quoting problems in user's DNs; (bso#11488).

  - s3-auth: Fix 'map to guest = Bad uid'; (bso#9862).

  - s4:lib/tls: Fix build with gnutls 3.4; (bso#8780).

  - s4.2/fsmo.py: Fixed fsmo transfer exception;
    (bso#10924).

  - winbindd: Sync secrets.ldb into secrets.tdb on startup;
    (bso#10991).

  - Logon via MS Remote Desktop hangs; (bso#11061).

  - s3: lib: util: Ensure we read a hex number as %x, not
    %u; (bso#11068).

  - tevent: Add a note to tevent_add_fd(); (bso#11141).

  - s3:param/loadparm: Fix 'testparm --show-all-parameters';
    (bso#11170).

  - s3-unix_msg: Remove socket file after closing socket fd;
    (bso#11217).

  - smbd: Fix a use-after-free; (bso#11218); (boo#919309).

  - s3-rpc_server: Fix rpc_create_tcpip_sockets() processing
    of interfaces; (bso#11245).

  - s3:smb2: Add padding to last command in compound
    requests; (bso#11277).

  - Add IPv6 support to ADS client side LDAP connects;
    (bso#11281).

  - Add IPv6 support for determining FQDN during ADS join;
    (bso#11282).

  - s3: IPv6 enabled DNS connections for ADS client;
    (bso#11283).

  - Fix invalid write in ctdb_lock_context_destructor;
    (bso#11293).

  - Excessive cli_resolve_path() usage can slow down
    transmission; (bso#11295).

  - vfs_fruit: Add option 'veto_appledouble'; (bso#11305).

  - tstream: Make socketpair nonblocking; (bso#11312).

  - idmap_rfc2307: Fix wbinfo '--gid-to-sid' query;
    (bso#11313).

  - Group creation: Add msSFU30Name only when --nis-domain
    was given; (bso#11315).

  - tevent_fd needs to be destroyed before closing the fd;
    (bso#11316).

  - Build fails on Solaris 11 with
    '&lsquo;PTHREAD_MUTEX_ROBUST&rsquo; undeclared';
    (bso#11319).

  - smbd/trans2: Add a useful diagnostic for files with bad
    encoding; (bso#11323).

  - Change sharesec output back to previous format;
    (bso#11324).

  - Robust mutex support broken in 1.3.5; (bso#11326).

  - Kerberos auth info3 should contain resource group ids
    available from pac_logon; winbindd:
    winbindd_raw_kerberos_login - ensure logon_info exists
    in PAC; (bso#11328); (boo#912457).

  - s3:smb2_setinfo: Fix memory leak in the defer_rename
    case; (bso#11329).

  - tevent: Fix CID 1035381 Unchecked return value;
    (bso#11330).

  - tdb: Fix CID 1034842 and 1034841 Resource leaks;
    (bso#11331).

  - s3: smbd: Use separate flag to track
    become_root()/unbecome_root() state; (bso#11339).

  - s3: smbd: Codenomicon crash in do_smb_load_module();
    (bso#11342).

  - pidl: Make the compilation of PIDL producing the same
    results if the content hasn't change; (bso#11356).

  - winbindd: Disconnect child process if request is
    cancelled at main process; (bso#11358).

  - vfs_fruit: Check offset and length for AFP_AfpInfo read
    requests; (bso#11363).

  - docs: Overhaul the description of 'smb encrypt' to
    include SMB3 encryption; (bso#11366).

  - s3:auth_domain: Fix talloc problem in
    connect_to_domain_password_server(); (bso#11367).

  - ncacn_http: Fix GNUism; (bso#11371).

  - Backport changes to use resource group sids obtained
    from pac logon_info; (bso#11328); (boo#912457).

  - Order winbind.service Before and Want nss-user-lookup
    target.

  - s3:smbXsrv: refactor duplicate code into
    smbXsrv_session_clear_and_logoff(); (bso#11182).

  - gencache: don't fail gencache_stabilize if there were
    records to delete; (bso#11260).

  - s3: libsmbclient: After getting attribute server, ensure
    main srv pointer is still valid; (bso#11186).

  - s4: rpc: Refactor dcesrv_alter() function into setup and
    send steps; (bso#11236).

  - s3: smbd: Incorrect file size returned in the response
    of 'FILE_SUPERSEDE Create'; (bso#11240).

  - Mangled names do not work with acl_xattr; (bso#11249).

  - nmbd rewrites browse.dat when not required; (bso#11254).

  - vfs_fruit: add option 'nfs_aces' that controls the NFS
    ACEs stuff; (bso#11213).

  - s3:smbd: Add missing tevent_req_nterror; (bso#11224).

  - vfs: kernel_flock and named streams; (bso#11243).

  - vfs_gpfs: Error code path doesn't call END_PROFILE;
    (bso#11244).

  - s4: libcli/finddcs_cldap: continue processing CLDAP
    until all addresses are used; (bso#11284).

  - ctdb: check for talloc_asprintf() failure; (bso#11201).

  - spoolss: purge the printer name cache on name change;
    (bso#11210); (boo#901813).

  - CTDB statd-callout does not scale; (bso#11204).

  - vfs_fruit: also map characters below 0x20; (bso#11221).

  - ctdb: Coverity fix for CID 1291643; (bso#11201).

  - Multiplexed RPC connections are not handled by DCERPC
    server; (bso#11225).

  - Fix terminate connection behavior for asynchronous
    endpoint with PUSH notification flavors; (bso#11226).

  - ctdb-scripts: Fix bashism in ctdbd_wrapper script;
    (bso#11007).

  - ctdb: Fix CIDs 1125615, 1125634, 1125613, 1288201 and
    1125553; (bso#11201).

  - SMB2 should cancel pending NOTIFY calls with
    DELETE_PENDING if the directory is deleted; (bso#11257).

  - s3:winbindd: make sure we remove pending io requests
    before closing client

  - 'sharesec' output no longer matches input format;
    (bso#11237).

  - waf: Fix systemd detection; (bso#11200).

  - CTDB: Fix portability issues; (bso#11202).

  - CTDB: Fix some IPv6-related issues; (bso#11203).

  - CTDB statd-callout does not scale; (bso#11204).

  - 'net ads dns gethostbyname' crashes with an error in
    TALLOC_FREE if you enter invalid values; (bso#11234).

  - libads: record service ticket endtime for sealed ldap
    connections;

  - lib/util: Include DEBUG macro in internal header files
    before samba_util.h; (bso#11033).

  - Initialize dwFlags field of DNS_RPC_NODE structure;
    (bso#9791).

  - s3: lib: ntlmssp: If NTLMSSP_NEGOTIATE_TARGET_INFO isn't
    set, cope with servers that don't send the 2 unused
    fields; (bso#10016).

  - build:wafadmin: Fix use of spaces instead of tabs;
    (bso#10476).

  - waf: Fix the build on openbsd; (bso#10476).

  - s3: client: 'client use spnego principal = yes' code
    checks wrong name;

  - spoolss: Retrieve published printer GUID if not in
    registry; (bso#11018).

  - vfs_fruit: Enhance handling of malformed AppleDouble
    files; (bso#11125).

  - backupkey: Explicitly link to gnutls and gcrypt;
    (bso#11135).

  - replace: Remove superfluous check for gcrypt header;
    (bso#11135).

  - Backport subunit changes; (bso#11137).

  - libcli/auth: Match Declaration of
    netlogon_creds_cli_context_tmp with implementation;
    (bso#11140).

  - s3-winbind: Fix cached user group lookup of trusted
    domains; (bso#11143).

  - talloc: Version 2.1.2; (bso#11144).

  - Update libwbclient version to 0.12; (bso#11149).

  - brlock: Use 0 instead of empty initializer list;
    (bso#11153).

  - s4:auth/gensec_gssapi: Let gensec_gssapi_update() return

  - backupkey: Use ndr_pull_struct_blob_all(); (bso#11174).

  - Fix lots of winbindd zombie processes on Solaris
    platform; (bso#11175).

  - Prevent samba package updates from disabling samba
    kerberos printing.

  - Add sparse file support for samba; (fate#318424).

  - Simplify libxslt build requirement and README.SUSE
    install.

  - Remove no longer required cleanup steps while populating
    the build root.

  - smbd: Stop using vfs_Chdir after SMB_VFS_DISCONNECT;
    (bso#1115).

  - pam_winbind: fix warn_pwd_expire implementation;
    (bso#9056).

  - nsswitch: Fix soname of linux nss_*.so.2 modules;
    (bso#9299).

  - Make 'profiles' work again; (bso#9629).

  - s3:smb2_server: protect against integer wrap with 'smb2
    max credits = 65535'; (bso#9702).

  - Make validate_ldb of String(Generalized-Time) accept
    millisecond format '.000Z'; (bso#9810).

  - Use -R linker flag on Solaris, not -rpath; (bso#10112).

  - vfs: Add glusterfs manpage; (bso#10240).

  - Make 'smbclient' use cached creds; (bso#10279).

  - pdb: Fix build issues with shared modules; (bso#10355).

  - s4-dns: Add support for BIND 9.10; (bso#10620).

  - idmap: Return the correct id type to *id_to_sid methods;
    (bso#10720).

  - printing/cups: Pack requested-attributes with
    IPP_TAG_KEYWORD; (bso#10808).

  - Don't build vfs_snapper on FreeBSD; (bso#10834).

  - nss_winbind: Add getgroupmembership for FreeBSD;
    (bso#10835).

  - idmap_rfc2307: Fix a crash after connection problem to
    DC; (bso#10837).

  - s3: smb2cli: query info return length check was
    reversed; (bso#10848).

  - s3: lib, s3: modules: Fix compilation on Solaris;
    (bso#10849).

  - lib: uid_wrapper: Fix setgroups and syscall detection on
    a system without native uid_wrapper library;
    (bso#10851).

  - winbind3: Fix pwent variable substitution; (bso#10852).

  - Improve samba-regedit; (bso#10859).

  - registry: Don't leave dangling transactions;
    (bso#10860).

  - Fix build of socket_wrapper on systems without
    SO_PROTOCOL; (bso#10861).

  - build: Do not install 'texpect' binary anymore;
    (bso#10862).

  - Fix testparm to show hidden share defaults; (bso#10864).

  - libcli/smb: Fix smb2cli_validate_negotiate_info with
    min=PROTOCOL_NT1 max=PROTOCOL_SMB2_02; (bso#10866).

  - Integrate CTDB into top-level Samba build; (bso#10892).

  - samba-tool group add: Add option '--nis-domain' and
    '--gid'; (bso#10895).

  - s3-nmbd: Fix netbios name truncation; (bso#10896).

  - spoolss: Fix handling of bad EnumJobs levels;
    (bso#10898).

  - Fix smbclient loops doing a directory listing against
    Mac OS X 10 server with a non-wildcard path;
    (bso#10904).

  - Fix print job enumeration; (bso#10905); (boo#898031).

  - samba-tool: Create NIS enabled users and
    unixHomeDirectory attribute; (bso#10909).

  - Add support for SMB2 leases; (bso#10911).

  - btrfs: Don't leak opened directory handle; (bso#10918).

  - s3: nmbd: Ensure NetBIOS names are only 15 characters
    stored; (bso#10920).

  - s3:smbd: Fix file corruption using 'write cache size !=
    0'; (bso#10921).

  - pdb_tdb: Fix a TALLOC/SAFE_FREE mixup; (bso#10932).

  - s3-keytab: fix keytab array NULL termination;
    (bso#10933).

  - s3:passdb: fix logic in pdb_set_pw_history();
    (bso#10940).

  - Cleanup add_string_to_array and usage; (bso#10942).

  - dbwrap_ctdb: Pass on mutex flags to tdb_open;
    (bso#10942).

  - Fix RootDSE search with extended dn control;
    (bso#10949).

  - Fix 'samba-tool dns serverinfo <server>' for IPv6;
    (bso#10952).

  - libcli/smb: only force signing of smb2 session setups
    when binding a new session; (bso#10958).

  - s3-smbclient: Return success if we listed the shares;
    (bso#10960).

  - s3-smbstatus: Fix exit code of profile output;
    (bso#10961).

  - socket_wrapper: Add missing prototype check for eventfd;
    (bso#10965).

  - libcli: SMB2: Pure SMB2-only negprot fix to make us
    behave as a Windows client does; (bso#10966).

  - vfs_streams_xattr: Check stream type; (bso#10971).

  - s3: smbd: Fix *allocate* calls to follow POSIX error
    return convention; (bso#10982).

  - vfs_fruit: Add support for AAPL; (bso#10983).

  - Fix spoolss IDL response marshalling when returning
    error without clearing info; (bso#10984).

  - dsdb-samldb: Check for extended access rights before we
    allow changes to userAccountControl; (bso#10993);
    CVE-2014-8143; (boo#914279).

  - Fix IPv6 support in CTDB; (bso#10996).

  - ctdb-daemon: Use correct tdb flags when enabling robust
    mutex support; (bso#11000).

  - vfs_streams_xattr: Add missing call to
    SMB_VFS_NEXT_CONNECT; (bso#11005).

  - s3-util: Fix authentication with long hostnames;
    (bso#11008).

  - ctdb-build: Fix build without xsltproc; (bso#11014).

  - packaging: Include CTDB man pages in the tarball;
    (bso#11014).

  - pdb_get_trusteddom_pw() fails with non valid UTF16
    random passwords; (bso#11016).

  - Make Sharepoint search show user documents; (bso#11022).

  - nss_wrapper: check for nss.h; (bso#11026).

  - Enable mutexes in gencache_notrans.tdb; (bso#11032).

  - tdb_wrap: Make mutexes easier to use; (bso#11032).

  - lib/util: Avoid collision which alread defined consumer
    DEBUG macro; (bso#11033).

  - winbind: Retry after SESSION_EXPIRED error in ping-dc;
    (bso#11034).

  - s3-libads: Fix a possible segfault in
    kerberos_fetch_pac(); (bso#11037).

  - vfs_fruit: Fix base_fsp name conversion; (bso#11039).

  - vfs_fruit: mmap under FreeBSD needs PROT_READ;
    (bso#11040).

  - Fix authentication using Kerberos (not AD); (bso#11044).

  - net: Fix sam addgroupmem; (bso#11051).

  - vfs_snapper: Correctly handles multi-byte DBus strings;
    (bso#11055); (boo#913238).

  - cli_connect_nb_send: Don't segfault on host == NULL;
    (bso#11058).

  - utils: Fix 'net time' segfault; (bso#11058).

  - libsmb: Provide authinfo domain for encrypted session
    referrals; (bso#11059).

  - s3-pam_smbpass: Fix memory leak in
    pam_sm_authenticate(); (bso#11066).

  - vfs_glusterfs: Add comments to the pipe(2) code;
    (bso#11069).

  - vfs/glusterfs: Change xattr key to match gluster key;
    (bso#11069).

  - vfs_glusterfs: Implement AIO support; (bso#11069).

  - s3-vfs: Fix developer build of vfs_ceph module;
    (bso#11070).

  - s3: netlogon: Ensure we don't call talloc_free on an
    uninitialized pointer; (bso#11077); CVE-2015-0240;
    (boo#917376).

  - vfs: Add a brief vfs_ceph manpage; (bso#11088).

  - s3: smbclient: Allinfo leaves the file handle open;
    (bso#11094).

  - Fix Win8.1 Credentials Manager issue after KB2992611 on
    Samba domain; (bso#11097).

  - debug: Set close-on-exec for the main log file FD;
    (bso#11100).

  - s3: smbd: leases - losen paranoia check. Stat opens can
    grant leases; (bso#11102).

  - s3: smbd: SMB2 close. If a file has delete on close,
    store the return info before deleting; (bso#11104).

  - doc:man:vfs_glusterfs: improve the configuration
    section; (bso#11117).

  - snprintf: Try to support %j; (bso#11119).

  - ctdb-io: Do not use sys_write to write to client
    sockets; (bso#11124).

  - doc-xml: Add 'sharesec' reference to 'access based share
    enum'; (bso#11127).

  - Fix usage of freed memory on server exit; (bso#11218);
    (boo#919309).

  - Adjust baselibs.conf due to libpdb0 package rename to
    libsamba-passdb0.

  - Add libsamba-debug, libsocket-blocking,
    libsamba-cluster-support, and libhttp to the libs
    package; (boo#913547).

  - Rebase File Server Remote VSS Protocol (FSRVP) server
    against 4.2.0rc1; (fate#313346)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=898031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=901813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=913238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=913547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=914279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=917376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=919309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=924519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=942716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=946051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=947552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974629"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-pcp-pmda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-pcp-pmda-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-atsvc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-atsvc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-atsvc0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-atsvc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-atsvc0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgensec-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgensec0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgensec0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgensec0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgensec0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libregistry-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libregistry0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libregistry0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libregistry0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libregistry0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-raw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-raw0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-raw0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-raw0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-raw0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/17");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"ctdb-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ctdb-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ctdb-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ctdb-pcp-pmda-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ctdb-pcp-pmda-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ctdb-tests-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ctdb-tests-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-atsvc-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-atsvc0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-atsvc0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-binding0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-binding0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-samr-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-samr0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc-samr0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdcerpc0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgensec-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgensec0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libgensec0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-krb5pac-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-krb5pac0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-krb5pac0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-nbt-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-nbt0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-nbt0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-standard-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-standard0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr-standard0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libndr0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libnetapi-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libnetapi0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libnetapi0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libregistry-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libregistry0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libregistry0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-credentials-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-credentials0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-credentials0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-hostconfig-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-hostconfig0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-hostconfig0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-passdb-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-passdb0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-passdb0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-policy-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-policy0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-policy0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-util-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-util0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamba-util0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamdb-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamdb0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsamdb0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbclient-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbclient-raw-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbclient-raw0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbclient-raw0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbclient0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbclient0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbconf-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbconf0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbconf0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbldap-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbldap0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmbldap0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtevent-util-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtevent-util0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtevent-util0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwbclient-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwbclient0-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libwbclient0-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-client-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-client-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-core-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-debugsource-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-libs-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-libs-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-pidl-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-python-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-python-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-test-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-test-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-test-devel-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-winbind-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"samba-winbind-debuginfo-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc-atsvc0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc-atsvc0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc-samr0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc-samr0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdcerpc0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgensec0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libgensec0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr-standard0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr-standard0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libndr0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libnetapi0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libnetapi0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libregistry0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libregistry0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-policy0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-policy0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-util0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamba-util0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamdb0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsamdb0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbclient-raw0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbclient0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbconf0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbconf0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbldap0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsmbldap0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtevent-util0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtevent-util0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libwbclient0-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-client-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-libs-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-libs-debuginfo-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-winbind-32bit-4.2.4-34.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-4.2.4-34.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-debuginfo / ctdb-devel / ctdb-pcp-pmda / etc");
}
