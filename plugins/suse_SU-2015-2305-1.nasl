#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2305-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87527);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2015-3223", "CVE-2015-5252", "CVE-2015-5296", "CVE-2015-5299", "CVE-2015-5330", "CVE-2015-8467");
  script_osvdb_id(131935, 131936, 131937, 131938, 131939, 131940);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : ldb, samba, talloc, tdb, tevent (SUSE-SU-2015:2305-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ldb, samba, talloc, tdb, tevent fixes the following
security issues and bugs :

The Samba LDB was updated to version 1.1.24 :

  - Fix ldap \00 search expression attack dos;
    CVE-2015-3223; (bso#11325)

  - Fix remote read memory exploit in ldb; CVE-2015-5330;
    (bso#11599)

  - Move ldb_(un)pack_data into ldb_module.h for testing

  - Fix installation of _ldb_text.py

  - Fix propagation of ldb errors through tdb

  - Fix bug triggered by having an empty message in database
    during search

Samba was updated to fix these issues :

  - Malicious request can cause Samba LDAP server to hang,
    spinning using CPU; CVE-2015-3223; (bso#11325);
    (bnc#958581).

  - Remote read memory exploit in LDB; CVE-2015-5330;
    (bso#11599); (bnc#958586).

  - Insufficient symlink verification (file access outside
    the share); CVE-2015-5252; (bso#11395); (bnc#958582).

  - No man in the middle protection when forcing smb
    encryption on the client side; CVE-2015-5296;
    (bso#11536); (bnc#958584).

  - Currently the snapshot browsing is not secure thru
    windows previous version (shadow_copy2); CVE-2015-5299;
    (bso#11529); (bnc#958583).

  - Fix Microsoft MS15-096 to prevent machine accounts from
    being changed into user accounts; CVE-2015-8467;
    (bso#11552); (bnc#958585).

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
    user; (bso#11569); (bnc#949022).

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

  - Cleanup and enhance the pidl sub package.

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

  - Prevent NULL pointer access in samlogon fallback when
    security credentials are null; (bnc#949022).

  - Fix 100% CPU in winbindd when logging in with 'user must
    change password on next logon'; (bso#11038).

talloc was updated to version 2.1.5; (bsc#954658) (bsc#951660).

  - Test that talloc magic differs between processes.

  - Increment minor version due to added
    talloc_test_get_magic.

  - Provide tests access to talloc_magic.

  - Test magic protection measures.

tdb was updated to version 1.3.8; (bsc#954658).

  - Improved python3 bindings

tevent was updated to 0.9.26; (bsc#954658).

  - New tevent_thread_proxy api

  - Minor build fixes

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3223.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5252.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5296.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5299.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5330.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8467.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152305-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b15b351"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2015-996=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2015-996=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2015-996=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ldb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgensec0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgensec0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libregistry0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libregistry0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-raw0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-raw0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtalloc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtalloc2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtdb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pytalloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pytalloc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:talloc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tdb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tdb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tdb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tevent-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"ldb-debugsource-1.1.24-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libldb1-1.1.24-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libldb1-debuginfo-1.1.24-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libregistry0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libregistry0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtalloc2-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtalloc2-debuginfo-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtdb1-1.3.8-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtdb1-debuginfo-1.3.8-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent0-0.9.26-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent0-debuginfo-0.9.26-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"pytalloc-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"pytalloc-debuginfo-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-debugsource-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"talloc-debugsource-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"tdb-debugsource-1.3.8-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"tdb-tools-1.3.8-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"tdb-tools-debuginfo-1.3.8-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"tevent-debugsource-0.9.26-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libldb1-32bit-1.1.24-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libldb1-debuginfo-32bit-1.1.24-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtalloc2-32bit-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtalloc2-debuginfo-32bit-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtdb1-32bit-1.3.8-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtdb1-debuginfo-32bit-1.3.8-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent0-32bit-0.9.26-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent0-debuginfo-32bit-0.9.26-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"pytalloc-32bit-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"pytalloc-debuginfo-32bit-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ldb-debugsource-1.1.24-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libldb1-1.1.24-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libldb1-32bit-1.1.24-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libldb1-debuginfo-1.1.24-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libldb1-debuginfo-32bit-1.1.24-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libregistry0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libregistry0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtalloc2-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtalloc2-32bit-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtalloc2-debuginfo-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtalloc2-debuginfo-32bit-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtdb1-1.3.8-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtdb1-32bit-1.3.8-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtdb1-debuginfo-1.3.8-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtdb1-debuginfo-32bit-1.3.8-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent0-0.9.26-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent0-32bit-0.9.26-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent0-debuginfo-0.9.26-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent0-debuginfo-32bit-0.9.26-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"pytalloc-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"pytalloc-32bit-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"pytalloc-debuginfo-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"pytalloc-debuginfo-32bit-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-debugsource-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-debuginfo-4.2.4-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"talloc-debugsource-2.1.5-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"tdb-debugsource-1.3.8-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"tevent-debugsource-0.9.26-4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldb / samba / talloc / tdb / tevent");
}
