#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2527-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(94067);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/27 20:24:10 $");

  script_cve_id("CVE-2016-3186", "CVE-2016-3622", "CVE-2016-3623", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-5314", "CVE-2016-5316", "CVE-2016-5317", "CVE-2016-5320", "CVE-2016-5875");
  script_osvdb_id(136448, 136741, 136837, 136839, 137083, 140006, 140016, 140118);

  script_name(english:"SUSE SLES11 Security Update : tiff (SUSE-SU-2016:2527-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tiff fixes the following issues :

  - CVE-2016-3622: Specially crafted TIFF images could
    trigger a crash in tiff2rgba (bsc#974449)

  - Various out-of-bound write vulnerabilities with
    unspecified impact (MSVR 35093, MSVR 35094, MSVR 35095,
    MSVR 35096, MSVR 35097, MSVR 35098)

  - CVE-2016-5314: Specially crafted TIFF images could
    trigger a crash that could result in DoS (bsc#984831)

  - CVE-2016-5316: Specially crafted TIFF images could
    trigger a crash in the rgb2ycbcr tool, leading to Doa
    (bsc#984837)

  - CVE-2016-5317: Specially crafted TIFF images could
    trigger a crash through an out of bound write
    (bsc#984842)

  - CVE-2016-5320: Specially crafted TIFF images could
    trigger a crash or potentially allow remote code
    execution when using the rgb2ycbcr command (bsc#984808)

  - CVE-2016-5875: Specially crafted TIFF images could
    trigger could allow arbitrary code execution
    (bsc#987351)

  - CVE-2016-3623: Specially crafted TIFF images could
    trigger a crash in rgb2ycbcr (bsc#974618)

  - CVE-2016-3945: Specially crafted TIFF images could
    trigger a crash or allow for arbitrary command execution
    via tiff2rgba (bsc#974614)

  - CVE-2016-3990: Specially crafted TIFF images could
    trigger a crash or allow for arbitrary command execution
    (bsc#975069)

  - CVE-2016-3186: Specially crafted TIFF imaged could
    trigger a crash in the gif2tiff command via a buffer
    overflow (bsc#973340)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975069"
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
    value:"https://www.suse.com/security/cve/CVE-2016-3186.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3622.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3623.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3945.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3990.html"
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
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162527-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c24b6b3b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-tiff-12785=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-tiff-12785=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-tiff-12785=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/14");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libtiff3-32bit-3.8.2-141.168.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libtiff3-32bit-3.8.2-141.168.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libtiff3-3.8.2-141.168.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"tiff-3.8.2-141.168.1")) flag++;


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
