#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1349 and 
# Oracle Linux Security Advisory ELSA-2011-1349 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68363);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:02:14 $");

  script_cve_id("CVE-2011-3378");
  script_bugtraq_id(49799);
  script_osvdb_id(75930, 75931);
  script_xref(name:"RHSA", value:"2011:1349");

  script_name(english:"Oracle Linux 4 / 5 / 6 : rpm (ELSA-2011-1349)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1349 :

Updated rpm packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4, 5, and 6, and Red Hat
Enterprise Linux 3 Extended Life Cycle Support, 5.3 Long Life, 5.6
Extended Update Support, and 6.0 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The RPM Package Manager (RPM) is a command line driven package
management system capable of installing, uninstalling, verifying,
querying, and updating software packages.

Multiple flaws were found in the way the RPM library parsed package
headers. An attacker could create a specially crafted RPM package
that, when queried or installed, would cause rpm to crash or,
potentially, execute arbitrary code. (CVE-2011-3378)

Note: Although an RPM package can, by design, execute arbitrary code
when installed, this issue would allow a specially crafted RPM package
to execute arbitrary code before its digital signature has been
verified. Package downloads from the Red Hat Network remain secure due
to certificate checks performed on the secure connection.

All RPM users should upgrade to these updated packages, which contain
a backported patch to correct these issues. All running applications
linked against the RPM library must be restarted for this update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-October/002385.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-October/002386.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-October/002387.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected rpm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:popt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rpm-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rpm-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rpm-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"popt-1.9.1-35_nonptl.el4")) flag++;
if (rpm_check(release:"EL4", reference:"rpm-4.3.3-35_nonptl.el4")) flag++;
if (rpm_check(release:"EL4", reference:"rpm-build-4.3.3-35_nonptl.el4")) flag++;
if (rpm_check(release:"EL4", reference:"rpm-devel-4.3.3-35_nonptl.el4")) flag++;
if (rpm_check(release:"EL4", reference:"rpm-libs-4.3.3-35_nonptl.el4")) flag++;
if (rpm_check(release:"EL4", reference:"rpm-python-4.3.3-35_nonptl.el4")) flag++;

if (rpm_check(release:"EL5", reference:"popt-1.10.2.3-22.0.1.el5_7.2")) flag++;
if (rpm_check(release:"EL5", reference:"rpm-4.4.2.3-22.0.1.el5_7.2")) flag++;
if (rpm_check(release:"EL5", reference:"rpm-apidocs-4.4.2.3-22.0.1.el5_7.2")) flag++;
if (rpm_check(release:"EL5", reference:"rpm-build-4.4.2.3-22.0.1.el5_7.2")) flag++;
if (rpm_check(release:"EL5", reference:"rpm-devel-4.4.2.3-22.0.1.el5_7.2")) flag++;
if (rpm_check(release:"EL5", reference:"rpm-libs-4.4.2.3-22.0.1.el5_7.2")) flag++;
if (rpm_check(release:"EL5", reference:"rpm-python-4.4.2.3-22.0.1.el5_7.2")) flag++;

if (rpm_check(release:"EL6", reference:"rpm-4.8.0-16.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"rpm-apidocs-4.8.0-16.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"rpm-build-4.8.0-16.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"rpm-cron-4.8.0-16.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"rpm-devel-4.8.0-16.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"rpm-libs-4.8.0-16.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"rpm-python-4.8.0-16.el6_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "popt / rpm / rpm-apidocs / rpm-build / rpm-cron / rpm-devel / etc");
}
