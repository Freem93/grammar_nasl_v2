#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2306-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93508);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/28 15:10:48 $");

  script_cve_id("CVE-2016-2119");
  script_osvdb_id(141072);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : samba (SUSE-SU-2016:2306-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for samba provides the following fixes :

  - CVE-2016-2119: Prevent client-side SMB2 signing
    downgrade. (bsc#986869)

  - Fix possible ctdb crash when opening sockets with
    htons(IPPROTO_RAW). (bsc#969522)

  - Honor smb.conf socket options in winbind. (bsc#975131)

  - Fix ntlm-auth segmentation fault with squid.
    (bsc#986228)

  - Implement new '--no-dns-updates' option in 'net ads'
    command. (bsc#991564)

  - Fix population of ctdb sysconfig after source merge.
    (bsc#981566)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2119.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162306-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21cc98df"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1350=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1350=1

SUSE Linux Enterprise High Availability 12-SP1:zypper in -t patch
SUSE-SLE-HA-12-SP1-2016-1350=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1350=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");
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
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libregistry0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libregistry0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-debugsource-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc-binding0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libdcerpc0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgensec0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-krb5pac0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-nbt0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr-standard0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libndr0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libnetapi0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-credentials0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-hostconfig0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-passdb0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamba-util0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsamdb0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient-raw0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbclient0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbconf0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsmbldap0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtevent-util0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libwbclient0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-client-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-libs-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"samba-winbind-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libdcerpc0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgensec0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr-standard0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libndr0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libnetapi0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libregistry0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libregistry0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamba-util0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsamdb0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient-raw0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbclient0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbconf0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsmbldap0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtevent-util0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwbclient0-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-client-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-debugsource-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-libs-debuginfo-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-4.2.4-26.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"samba-winbind-debuginfo-4.2.4-26.2")) flag++;


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
