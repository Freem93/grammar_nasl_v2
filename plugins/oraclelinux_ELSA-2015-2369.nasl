#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:2369 and 
# Oracle Linux Security Advisory ELSA-2015-2369 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87036);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/28 19:11:31 $");

  script_cve_id("CVE-2015-3248");
  script_osvdb_id(123523);
  script_xref(name:"RHSA", value:"2015:2369");

  script_name(english:"Oracle Linux 7 : openhpi (ELSA-2015-2369)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:2369 :

Updated openhpi packages that fix one security issue, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

OpenHPI is an open source project created with the intent of providing
an implementation of the SA Forum's Hardware Platform Interface (HPI).
HPI provides an abstracted interface to managing computer hardware,
typically for chassis and rack based servers. HPI includes resource
modeling, access to and control over sensor, control, watchdog, and
inventory data associated with resources, abstracted System Event Log
interfaces, hardware events and alerts, and a managed hotswap
interface.

It was found that the '/var/lib/openhpi' directory provided by OpenHPI
used world-writeable and world-readable permissions. A local user
could use this flaw to view, modify, and delete OpenHPI-related data,
or even fill up the storage device hosting the /var/lib directory.
(CVE-2015-3248)

This issue was discovered by Marko Myllynen of Red Hat.

The openhpi packages have been upgraded to upstream version 3.4.0,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#1127908)

This update also fixes the following bug :

* Network timeouts were handled incorrectly in the openhpid daemon. As
a consequence, network connections could fail when external plug-ins
were used. With this update, handling of network socket timeouts has
been improved in openhpid, and the described problem no longer occurs.
(BZ#1208127)

All openhpi users are advised to upgrade to these updated packages,
which correct these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-November/005568.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openhpi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openhpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openhpi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openhpi-libs");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openhpi-3.4.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openhpi-devel-3.4.0-2.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openhpi-libs-3.4.0-2.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openhpi / openhpi-devel / openhpi-libs");
}
