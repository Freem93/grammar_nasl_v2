#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-399.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90173);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:11 $");

  script_cve_id("CVE-2015-7560");

  script_name(english:"openSUSE Security Update : samba (openSUSE-2016-399)");
  script_summary(english:"Check for the openSUSE-2016-399 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for the samba server fixes the following issues :

Security issue fixed :

  - CVE-2015-7560: Getting and setting Windows ACLs on
    symlinks can change permissions on link target;
    (bso#11648); (bsc#968222).

Other bugs fixed :

  - Enable clustering (CTDB) support; (bsc#966271).

  - s3: smbd: Fix timestamp rounding inside SMB2 create;
    (bso#11703); (bsc#964023).

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

  - Add quotes around path of update-apparmor-samba-profile;
    (bsc#962177).

  - Prevent access denied if the share path is '/';
    (bso#11647); (bsc#960249).

  - Ensure samlogon fallback requests are rerouted after
    kerberos failure; (bsc#953972).

  - samba: winbind crash ->
    netlogon_creds_client_authenticator; (bsc#953972)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962177"
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
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-devel");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"ctdb-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ctdb-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ctdb-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ctdb-tests-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ctdb-tests-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-atsvc-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-atsvc0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-atsvc0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-binding0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-binding0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-samr-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-samr0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc-samr0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libdcerpc0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgensec-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgensec0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libgensec0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-krb5pac-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-krb5pac0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-krb5pac0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-nbt-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-nbt0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-nbt0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-standard-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-standard0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr-standard0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libndr0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libnetapi-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libnetapi0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libnetapi0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libregistry-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libregistry0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libregistry0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-credentials-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-credentials0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-credentials0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-hostconfig-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-hostconfig0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-hostconfig0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-passdb-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-passdb0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-passdb0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-policy-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-policy0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-policy0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-util-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-util0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamba-util0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamdb-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamdb0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsamdb0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbclient-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbclient-raw-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbclient-raw0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbclient-raw0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbclient0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbclient0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbconf-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbconf0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbconf0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbldap-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbldap0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsmbldap0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtevent-util-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtevent-util0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtevent-util0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwbclient-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwbclient0-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libwbclient0-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-client-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-client-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-core-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-debugsource-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-libs-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-libs-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-pidl-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-python-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-python-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-test-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-test-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-test-devel-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-winbind-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"samba-winbind-debuginfo-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc-atsvc0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc-atsvc0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc-samr0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc-samr0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libdcerpc0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgensec0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libgensec0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr-standard0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr-standard0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libndr0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libnetapi0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libnetapi0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libregistry0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libregistry0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-policy0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-policy0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-util0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamba-util0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamdb0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsamdb0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbclient-raw0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbclient0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbconf0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbconf0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbldap0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsmbldap0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtevent-util0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtevent-util0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libwbclient0-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-client-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-libs-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-libs-debuginfo-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-winbind-32bit-4.2.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-4.2.4-12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-debuginfo / ctdb-devel / ctdb-tests / etc");
}
