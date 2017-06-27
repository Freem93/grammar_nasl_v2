#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-109.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74545);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-0817");

  script_name(english:"openSUSE Security Update : samba (openSUSE-2012-109)");
  script_summary(english:"Check for the openSUSE-2012-109 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fix memory leak in parent smbd on connection;
    CVE-2012-0817; (bso#8724); (bnc#743986).

  - Use spdx.org compliant license names for all packages.

  - Update to 3.6.2.

See WHATSNEW.txt from the main tar ball or the samba.changes file for
more details.

  - s3-spoolss: Pass the right pointer type; (bso#4942);
    (bnc#742504).

  - Use correct license, LGPLv3+ for libwbclient packages.

  - When returning an ACL without SECINFO_DACL requested, we
    still set SEC_DESC_DACL_PRESENT in the type field;
    (bso#8636).

  - Prefix print$ path on driver file deletion; (bso#8697);
    (bnc#740810).

  - Fix printer_driver_files_in_use() call ordering;
    (bso#4942); (bnc#742504).

  - Buffer overflow issue with AES encryption in samba
    traffic analyzer; (bso#8674).

  - NT ACL issue; (bso#8673).

  - Deleting a symlink fails if the symlink target is
    outside of the share; (bso#8663).

  - connections.tdb - major leak with SMB2; (bso#8710).

  - Renaming a symlink fails if the symlink target is
    outside of the share; (bso#8664).

  - Intermittent print job failures caused by character
    conversion errors; (bso#8606).

  - ads_keytab_verify_ticket mixes talloc allocation with
    malloc free; (bso#8692).

  - libcli/cldap: fix a crash bug in
    cldap_socket_recv_dgram(); (bso#8593).

  - s3:lib/ctdbd_conn: try ctdbd_init_connection() as root;
    (bso#8684).

  - s3-printing: fix migrate printer code; (bso#8618).

  - Packet validation checks can be done before length
    validation causing uninitialized memory read;
    (bso#8686).

  - net memberships usage info was wrong; (bso#8687).

  - s3-libsmb: Don't duplicate kerberos service tickets;
    (bso#8628).

  - Recvfile code path using splice() on Linux leaves data
    in the pipe on short write; (bso#8679).

  - s3-winbind: Fix segfault if we can't map the last user;
    (bso#8678).

  - vfs_acl_xattr and vfs_acl_tdb modules can fail to add
    inheritable entries on a directory with no stored ACL;
    (bso#8644).

  - s3/doc: document the ignore system acls option of
    vfs_acl_xattr and vfs_acl_tdb; (bso#8652).

  - Winbind can't receive any user/group information;
    (bso#8371).

  - s3-winbind: Add an update function for winbind cache;
    (bso#8643).

  - s3: Attempt to fix the vfs_commit module.

  - POSIX ACE x permission becomes rx following mapping to
    and from a DACL; (#bso#8631).

  - s3:libsmb: only align unicode pipe_name; (bso#8586).

  - s3-winbind: Don't fail on users without a uid;
    (bso#8608).

  - Crash when trying to browse samba printers; (bso#8623).

  - talloc: double free error; (bso#8562).

  - cldap doesn't work over ipv6; (bso#8600).

  - s3:libsmb: fix cli_write_and_x() against OS/2 print
    shares; (bso#5326).

  - SMB2: not granting credits for all requests in a
    compound request; (bso#8614).

  - smb2_flush sends uninitialized memory; (bso#8579).

  - Password change settings not fully observed; (bso#8561).

  - s3:smb2_server: grant credits in async interim
    responses; (bso#8357).

  - s3:smbd: don't limit the number of open dptrs for smb2;
    (bso#8592).

  - samr_ChangePasswordUser3 IDL incorrect; (bso#8591).

  - idmap_autorid does not have allocation pool; (bso#8444).

  - Add systemd service files.

  - s3:libsmb: the workgroup in the non-extended-security
    negprot is not aligned; (bso#8573).

  - s3-build: Fix inotify detection; (bso#8580).

  - SMB2 doesn't handle compound request headers in the same
    way as Windows; (#bso8560).

  - Disconnecting clients swamp the logs; (bso#8585).

  - s3-netlogon: Fix setting the machinge account password;
    (bso#8550).

  - winbind_samlogon_retry_loop ignores logon_parameters
    flags; (#bso8548). 

  - smbclient posix_open command fails to return correct
    info on open file; (bso#8542).

  - readlink() on Linux clients fails if the symlink target
    is outside of the share; (bso#8541).

  - s3-netapi: remove pointless use_memory_krb5_ccache;
    (bso#7465).

  - s3:Makefile: make DSO_EXPORTS_CMD more portable;
    (bso#8531).

  - s3:registry: fix the test for a REG_SZ blob possibly
    being a zero terminated ucs2 string; (bso#8528).

  - Make VFS op 'streaminfo' stackable; (bso#8419).

  - Fix incorrect perfcount array length calculations;
    (bnc#739258).

  - BuildRequire autoconf to avoid implicit dependency for
    post-11.4 systems.

  - Remove call to suse_update_config macro for post-11.4
    systems.

  - Use samba.org for the ldapsmb source location.

  - Fixing libsmbsharemode dependency on ldap and krb5 libs
    in Makefile; (bnc #729516).

  - Add ldap to Should-Start and Stop of the smb init
    script; (bnc#730046).

  - Fix smbd srv_spoolss_replycloseprinter() segfault;
    (bso#8384); (bnc#731571).

  - Fix pam_winbind.so segfault in pam_sm_authenticate();
    (bso#8564).

  - Fix smbclient >8GB tars on big endian machines;
    (bso#563); (bnc#726145).

  - Fix typo in net ads join output; (bnc#713135).

  - Add 'ldapsam:login cache' parameter to allow explicit
    disabling of the login cache; (bnc#723261).

  - Fix samba duplicates file content on appending. Move
    posix case semantics out from under the VFS; (bso#6898);
    (bnc#681208).

  - Make winbind child reconnect when remote end has closed,
    fix failing sudo; (bso#7295); (bnc#569721).

  - Fix printing from Windows 7 clients; (bso#7567);
    (bnc#687535).

  - Update pidl and always compile IDL at build time;
    (bnc#688810).

  - Abide by print$ share 'force user' & 'force group'
    settings when handling AddprinterDriver and
    DeletePrinterDriver requests; (bso#7921); (bnc#653353)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=569721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=653353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=687535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=688810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=713135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=723261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=729516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=730046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=731571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=739258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=742504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=743986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744614"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldapsmb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0-debuginfo-32bit");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-krb-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-krb-printing-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"ldapsmb-1.34b-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libldb-devel-1.0.2-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libldb1-1.0.2-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libldb1-debuginfo-1.0.2-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnetapi-devel-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnetapi0-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnetapi0-debuginfo-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbclient-devel-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbclient0-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbclient0-debuginfo-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbsharemodes-devel-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbsharemodes0-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsmbsharemodes0-debuginfo-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtalloc-devel-2.0.5-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtalloc2-2.0.5-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtalloc2-debuginfo-2.0.5-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtdb-devel-1.2.9-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtdb1-1.2.9-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtdb1-debuginfo-1.2.9-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtevent-devel-0.9.11-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtevent0-0.9.11-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtevent0-debuginfo-0.9.11-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libwbclient-devel-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libwbclient0-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libwbclient0-debuginfo-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-client-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-client-debuginfo-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-debuginfo-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-debugsource-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-devel-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-krb-printing-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-krb-printing-debuginfo-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-winbind-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"samba-winbind-debuginfo-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libldb1-32bit-1.0.2-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libldb1-debuginfo-32bit-1.0.2-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtalloc2-32bit-2.0.5-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtalloc2-debuginfo-32bit-2.0.5-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtdb1-32bit-1.2.9-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtdb1-debuginfo-32bit-1.2.9-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtevent0-32bit-0.9.11-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libtevent0-debuginfo-32bit-0.9.11-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-32bit-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-client-32bit-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-debuginfo-32bit-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.3-34.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-3.6.3-34.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldapsmb / libldb-devel / libldb1 / libldb1-32bit / etc");
}
