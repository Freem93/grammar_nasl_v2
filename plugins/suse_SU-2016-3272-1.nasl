#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:3272-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(96149);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/05/15 14:02:24 $");

  script_cve_id("CVE-2016-2123", "CVE-2016-2125", "CVE-2016-2126");
  script_osvdb_id(14470, 149000, 149001, 149002);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : samba (SUSE-SU-2016:3272-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for samba fixes the following issues: Security issues
fixed :

  - CVE-2016-2125: Don't send delegated credentials to all
    servers. (bsc#1014441).

  - CVE-2016-2126: Denial of service due to a client
    triggered crash in the winbindd parent process.
    (bsc#1014442).

  - CVE-2016-2123: Heap-based Buffer Overflow Remote Code
    Execution Vulnerability. (bsc#1014437). The component
    affected is not built in our packages. Non security
    issues fixed :

  - s3/client: obey 'disable netbios' smb.conf param, don't
    connect via NBT port; (bsc#1009085)

  - Add doc changes for net ads --no-dns-updates switch;
    (bsc#991564)

  - Include vfstest in samba-test; (bsc#1001203).

  - s3/winbindd: using default domain with user@domain.com
    format fails (bsc#997833).

  - Fix illegal memory access after memory has been deleted
    (bsc#975299).

  - Fix bug in tevent poll backend causing winbind to loop
    tightly (bsc#994500).

  - Various fixes for spnego/ntlm (bsc#986675).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1001203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2123.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2125.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2126.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20163272-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58bdc278"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2016-1917=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1917=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2016-1917=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2016-1917=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1917=1

SUSE Linux Enterprise High Availability 12-SP1:zypper in -t patch
SUSE-SLE-HA-12-SP1-2016-1917=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2016-1917=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1917=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-atsvc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-atsvc0-debuginfo");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"1999/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libregistry0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libregistry0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-debugsource-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libdcerpc-atsvc0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libdcerpc-atsvc0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libregistry0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libregistry0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-debugsource-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-debuginfo-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libdcerpc-atsvc0-4.2.4-28.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libdcerpc-atsvc0-debuginfo-4.2.4-28.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
