#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1228-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(90913);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/27 20:24:08 $");

  script_cve_id("CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2108", "CVE-2016-2109");
  script_osvdb_id(137577, 137896, 137898, 137899, 137900);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : openssl (SUSE-SU-2016:1228-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssl fixes the following issues :

  - CVE-2016-2108: Memory corruption in the ASN.1 encoder
    (bsc#977617)

  - CVE-2016-2107: Padding oracle in AES-NI CBC MAC check
    (bsc#977616)

  - CVE-2016-2105: EVP_EncodeUpdate overflow (bsc#977614)

  - CVE-2016-2106: EVP_EncryptUpdate overflow (bsc#977615)

  - CVE-2016-2109: ASN.1 BIO excessive memory allocation
    (bsc#976942)

  - bsc#976943: Buffer overrun in ASN1_parse

  - bsc#977621: Preserve negotiated digests for SNI
    (bsc#977621)

  - bsc#958501: Fix openssl enc -non-fips-allow option in
    FIPS mode (bsc#958501)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2105.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2106.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2107.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2108.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2109.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161228-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?46eb69b7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-715=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-715=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-715=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/05");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-1.0.1i-27.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-debuginfo-1.0.1i-27.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-hmac-1.0.1i-27.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssl-1.0.1i-27.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssl-debuginfo-1.0.1i-27.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssl-debugsource-1.0.1i-27.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-32bit-1.0.1i-27.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1i-27.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-hmac-32bit-1.0.1i-27.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl1_0_0-1.0.1i-27.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.1i-27.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-1.0.1i-27.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1i-27.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssl-1.0.1i-27.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssl-debuginfo-1.0.1i-27.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssl-debugsource-1.0.1i-27.16.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
