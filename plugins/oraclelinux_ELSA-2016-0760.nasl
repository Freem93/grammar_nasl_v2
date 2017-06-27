#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:0760 and 
# Oracle Linux Security Advisory ELSA-2016-0760 respectively.
#

include("compat.inc");

if (description)
{
  script_id(91149);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/05/26 16:04:32 $");

  script_cve_id("CVE-2014-3538", "CVE-2014-3587", "CVE-2014-3710", "CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9620", "CVE-2014-9653");
  script_osvdb_id(79681, 104208, 113614, 115923, 115924, 117591, 118387);
  script_xref(name:"RHSA", value:"2016:0760");

  script_name(english:"Oracle Linux 6 : file (ELSA-2016-0760)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:0760 :

An update for file is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The file command is used to identify a particular file according to
the type of data the file contains. It can identify many different
file types, including Executable and Linkable Format (ELF) binary
files, system libraries, RPM packages, and different graphics formats.

Security Fix(es) :

* Multiple flaws were found in the file regular expression rules for
detecting various files. A remote attacker could use these flaws to
cause file to consume an excessive amount of CPU. (CVE-2014-3538)

* A denial of service flaw was found in the way file parsed certain
Composite Document Format (CDF) files. A remote attacker could use
this flaw to crash file via a specially crafted CDF file.
(CVE-2014-3587)

* Multiple flaws were found in the way file parsed Executable and
Linkable Format (ELF) files. A remote attacker could use these flaws
to cause file to crash, disclose portions of its memory, or consume an
excessive amount of system resources. (CVE-2014-3710, CVE-2014-8116,
CVE-2014-8117, CVE-2014-9620, CVE-2014-9653)

Red Hat would like to thank Thomas Jarosch (Intra2net AG) for
reporting CVE-2014-8116 and CVE-2014-8117. The CVE-2014-3538 issue was
discovered by Jan Kaluza (Red Hat Web Stack Team) and the
CVE-2014-3710 issue was discovered by Francisco Alonso (Red Hat
Product Security).

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.8 Release Notes and Red Hat Enterprise Linux 6.8
Technical Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-May/006057.html"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"file-5.04-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"file-devel-5.04-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"file-libs-5.04-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"file-static-5.04-30.el6")) flag++;
if (rpm_check(release:"EL6", reference:"python-magic-5.04-30.el6")) flag++;


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
