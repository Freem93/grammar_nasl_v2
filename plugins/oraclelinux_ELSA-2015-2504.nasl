#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:2504 and 
# Oracle Linux Security Advisory ELSA-2015-2504 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87042);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 19:11:31 $");

  script_cve_id("CVE-2015-5302");
  script_osvdb_id(129048);
  script_xref(name:"RHSA", value:"2015:2504");

  script_name(english:"Oracle Linux 6 : libreport (ELSA-2015-2504)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:2504 :

Updated libreport packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

libreport provides an API for reporting different problems in
applications to different bug targets, such as Bugzilla, FTP, and
Trac. ABRT (Automatic Bug Reporting Tool) uses libreport.

It was found that ABRT may have exposed unintended information to Red
Hat Bugzilla during crash reporting. A bug in the libreport library
caused changes made by a user in files included in a crash report to
be discarded. As a result, Red Hat Bugzilla attachments may contain
data that was not intended to be made public, including host names, IP
addresses, or command line options. (CVE-2015-5302)

This flaw did not affect default installations of ABRT on Red Hat
Enterprise Linux as they do not post data to Red Hat Bugzilla. This
feature can however be enabled, potentially impacting modified ABRT
instances.

As a precaution, Red Hat has identified bugs filed by such non-default
Red Hat Enterprise Linux users of ABRT and marked them private.

This issue was discovered by Bastien Nocera of Red Hat.

All users of libreport are advised to upgrade to these updated
packages, which corrects this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-November/005552.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreport packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-plugin-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-plugin-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-plugin-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-plugin-mailx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-plugin-reportuploader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-plugin-ureport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libreport-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"libreport-2.0.9-25.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libreport-cli-2.0.9-25.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libreport-compat-2.0.9-25.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libreport-devel-2.0.9-25.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libreport-filesystem-2.0.9-25.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libreport-gtk-2.0.9-25.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libreport-gtk-devel-2.0.9-25.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libreport-newt-2.0.9-25.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libreport-plugin-bugzilla-2.0.9-25.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libreport-plugin-kerneloops-2.0.9-25.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libreport-plugin-logger-2.0.9-25.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libreport-plugin-mailx-2.0.9-25.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libreport-plugin-reportuploader-2.0.9-25.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libreport-plugin-ureport-2.0.9-25.0.1.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libreport-python-2.0.9-25.0.1.el6_7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreport / libreport-cli / libreport-compat / libreport-devel / etc");
}
