#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2271-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93439);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/01/23 15:32:05 $");

  script_cve_id("CVE-2015-8781", "CVE-2015-8782", "CVE-2015-8783", "CVE-2016-3186", "CVE-2016-5314", "CVE-2016-5316", "CVE-2016-5317", "CVE-2016-5320", "CVE-2016-5875");
  script_osvdb_id(133559, 133560, 133561, 133569, 136448, 140006, 140016, 140118);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : tiff (SUSE-SU-2016:2271-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tiff fixes the following issues :

  - CVE-2015-8781, CVE-2015-8782, CVE-2015-8783:
    Out-of-bounds writes for invalid images (bsc#964225)

  - CVE-2016-3186: Buffer overflow in gif2tiff (bnc#973340).

  - CVE-2016-5875: heap-based buffer overflow when using the
    PixarLog compressionformat (bsc#987351)

  - CVE-2016-5316: Out-of-bounds read in PixarLogCleanup()
    function in tif_pixarlog.c (bsc#984837)

  - CVE-2016-5314: Out-of-bounds write in PixarLogDecode()
    function (bsc#984831)

  - CVE-2016-5317: Out-of-bounds write in PixarLogDecode()
    function in libtiff.so (bsc#984842)

  - CVE-2016-5320: Out-of-bounds write in PixarLogDecode()
    function in tif_pixarlog.c (bsc#984808)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8781.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8782.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8783.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3186.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5314.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5316.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5317.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5320.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5875.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162271-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04f3fa40"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1330=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1330=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1330=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tiff-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/12");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtiff5-4.0.6-26.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtiff5-debuginfo-4.0.6-26.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"tiff-4.0.6-26.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"tiff-debuginfo-4.0.6-26.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"tiff-debugsource-4.0.6-26.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtiff5-32bit-4.0.6-26.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtiff5-debuginfo-32bit-4.0.6-26.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtiff5-32bit-4.0.6-26.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtiff5-4.0.6-26.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.6-26.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtiff5-debuginfo-4.0.6-26.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"tiff-debuginfo-4.0.6-26.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"tiff-debugsource-4.0.6-26.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tiff");
}
