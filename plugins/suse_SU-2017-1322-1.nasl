#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1322-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(100264);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/18 13:19:45 $");

  script_cve_id("CVE-2017-8291");
  script_osvdb_id(156431);

  script_name(english:"SUSE SLES11 Security Update : ghostscript-library (SUSE-SU-2017:1322-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ghostscript fixes the following security 
vulnerability :

  - CVE-2017-8291: A remote command execution and a -dSAFER
    bypass via a crafted .eps document were exploited in the
    wild. (bsc#1036453) This update is a reissue including
    the SUSE Linux Enterprise 11 SP3 product.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1036453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8291.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171322-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9318d483"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5:zypper in -t patch
sleclo50sp3-ghostscript-library-13109=1

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-ghostscript-library-13109=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-ghostscript-library-13109=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-ghostscript-library-13109=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-ghostscript-library-13109=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-ghostscript-library-13109=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-ghostscript-library-13109=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-fonts-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-fonts-rus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-fonts-std");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-library");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-omni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgimpprint");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"ghostscript-fonts-other-8.62-32.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"ghostscript-fonts-rus-8.62-32.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"ghostscript-fonts-std-8.62-32.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"ghostscript-library-8.62-32.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"ghostscript-omni-8.62-32.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"ghostscript-x11-8.62-32.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libgimpprint-4.2.7-32.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"ghostscript-fonts-other-8.62-32.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"ghostscript-fonts-rus-8.62-32.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"ghostscript-fonts-std-8.62-32.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"ghostscript-library-8.62-32.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"ghostscript-omni-8.62-32.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"ghostscript-x11-8.62-32.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libgimpprint-4.2.7-32.46.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript-library");
}
