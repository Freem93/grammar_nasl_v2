#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1024-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(90534);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/12/27 20:24:08 $");

  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2115", "CVE-2016-2118");
  script_osvdb_id(136339, 136989, 136990, 136991, 136992, 136993, 136995);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : samba (SUSE-SU-2016:1024-1) (Badlock)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"samba was updated to fix seven security issues.

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

These non-security issues were fixed :

  - bsc#974629: Fix samba.tests.messaging test and prevent
    potential tdb corruption by removing obsolete now
    invalid tdb_close call.

  - bsc#973832: Obsolete libsmbsharemodes0 from samba-libs
    and libsmbsharemodes-devel from samba-core-devel.

  - bsc#972197: Obsolete libsmbclient from libsmbclient0 and
    libpdb-devel from libsamba-passdb-devel while not
    providing it.

  - Getting and setting Windows ACLs on symlinks can change
    permissions on link

  - bsc#924519: Upgrade on-disk FSRVP server state to new
    version.

  - bsc#968973: Only obsolete but do not provide gplv2/3
    package names.

  - bso#6482: s3:utils/smbget: Fix recursive download.

  - bso#10489: s3: smbd: posix_acls: Fix check for setting
    u:g:o entry on a filesystem with no ACL support.

  - bso#11643: docs: Add example for domain logins to
    smbspool man page.

  - bso#11690: s3-client: Add a KRB5 wrapper for smbspool.

  - bso#11708: loadparm: Fix memory leak issue.

  - bso#11714: lib/tsocket: Work around sockets not
    supporting FIONREAD.

  - bso#11719: ctdb-scripts: Drop use of 'smbcontrol
    winbindd ip-dropped ...'.

  - bso#11727: s3:smbd:open: Skip redundant call to
    file_set_dosmode when creating a new file.

  - bso#11732: param: Fix str_list_v3 to accept ';' again.

  - bso#11740: Real memeory leak(buildup) issue in loadparm.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5370.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2110.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2111.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2112.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2113.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2115.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2118.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161024-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a539f801"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-604=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-604=1

SUSE Linux Enterprise High Availability 12-SP1 :

zypper in -t patch SUSE-SLE-HA-12-SP1-2016-604=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-604=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgensec0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgensec0-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libregistry0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libregistry0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-debugsource-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libregistry0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libregistry0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-debugsource-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-debuginfo-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-4.2.4-16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-debuginfo-4.2.4-16.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
