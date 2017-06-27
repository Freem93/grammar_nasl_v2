#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:2155 and 
# Oracle Linux Security Advisory ELSA-2015-2155 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87027);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/26 16:04:32 $");

  script_cve_id("CVE-2014-0207", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-3538", "CVE-2014-3587", "CVE-2014-3710", "CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9652", "CVE-2014-9653");
  script_osvdb_id(79681, 104208, 107559, 107560, 108463, 108464, 108465, 108466, 108467, 113614, 115011, 115923, 115924, 118387);
  script_xref(name:"RHSA", value:"2015:2155");

  script_name(english:"Oracle Linux 7 : file (ELSA-2015-2155)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:2155 :

Updated file packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The file command is used to identify a particular file according to
the type of data the file contains. It can identify many different
file types, including Executable and Linkable Format (ELF) binary
files, system libraries, RPM packages, and different graphics formats.

Multiple denial of service flaws were found in the way file parsed
certain Composite Document Format (CDF) files. A remote attacker could
use either of these flaws to crash file, or an application using file,
via a specially crafted CDF file. (CVE-2014-0207, CVE-2014-0237,
CVE-2014-0238, CVE-2014-3479, CVE-2014-3480, CVE-2014-3487,
CVE-2014-3587)

Two flaws were found in the way file processed certain Pascal strings.
A remote attacker could cause file to crash if it was used to identify
the type of the attacker-supplied file. (CVE-2014-3478, CVE-2014-9652)

Multiple flaws were found in the file regular expression rules for
detecting various files. A remote attacker could use these flaws to
cause file to consume an excessive amount of CPU. (CVE-2014-3538)

Multiple flaws were found in the way file parsed Executable and
Linkable Format (ELF) files. A remote attacker could use these flaws
to cause file to crash, disclose portions of its memory, or consume an
excessive amount of system resources. (CVE-2014-3710, CVE-2014-8116,
CVE-2014-8117, CVE-2014-9653)

Red Hat would like to thank Thomas Jarosch of Intra2net AG for
reporting the CVE-2014-8116 and CVE-2014-8117 issues. The
CVE-2014-0207, CVE-2014-0237, CVE-2014-0238, CVE-2014-3478,
CVE-2014-3479, CVE-2014-3480, CVE-2014-3487, CVE-2014-3710 issues were
discovered by Francisco Alonso of Red Hat Product Security; the
CVE-2014-3538 issue was discovered by Jan Kaluza of the Red Hat Web
Stack Team

The file packages have been updated to ensure correct operation on
Power little endian and ARM 64-bit hardware architectures.
(BZ#1224667, BZ#1224668, BZ#1157850, BZ#1067688).

All file users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-November/005562.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected file packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:file-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:file-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:file-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-magic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"file-5.11-31.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"file-devel-5.11-31.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"file-libs-5.11-31.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"file-static-5.11-31.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-magic-5.11-31.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file / file-devel / file-libs / file-static / python-magic");
}
