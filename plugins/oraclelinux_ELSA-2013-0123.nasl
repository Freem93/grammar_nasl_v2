#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0123 and 
# Oracle Linux Security Advisory ELSA-2013-0123 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68694);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/08/22 14:13:37 $");

  script_cve_id("CVE-2011-4339");
  script_bugtraq_id(51036);
  script_osvdb_id(77748);
  script_xref(name:"RHSA", value:"2013:0123");

  script_name(english:"Oracle Linux 5 : OpenIPMI (ELSA-2013-0123)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0123 :

Updated OpenIPMI packages that fix one security issue, multiple bugs,
and add one enhancement are now available for Red Hat Enterprise Linux
5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The OpenIPMI packages provide command line tools and utilities to
access platform information using Intelligent Platform Management
Interface (IPMI). System administrators can use OpenIPMI to manage
systems and to perform system health monitoring.

It was discovered that the IPMI event daemon (ipmievd) created its
process ID (PID) file with world-writable permissions. A local user
could use this flaw to make the ipmievd init script kill an arbitrary
process when the ipmievd daemon is stopped or restarted.
(CVE-2011-4339)

Note: This issue did not affect the default configuration of OpenIPMI
as shipped with Red Hat Enterprise Linux 5.

This update also fixes the following bugs :

* Prior to this update, the ipmitool utility first checked the IPMI
hardware for Dell IPMI extensions and listed only supported commands
when printing command usage like the option 'ipmtool delloem help'. On
a non-Dell platform, the usage text was incomplete and misleading.
This update lists all Dell OEM extensions in usage texts on all
platforms, which allows users to check for command line arguments on
non-Dell hardware. (BZ#658762)

* Prior to this update, the ipmitool utility tried to retrieve the
Sensor Data Records (SDR) from the IPMI bus instead of the Baseboard
Management Controller (BMC) bus when IPMI-enabled devices reported SDR
under a different owner than the BMC. As a consequence, the timeout
setting for the SDR read attempt could significantly decrease the
performance and no sensor data was shown. This update modifies
ipmitool to read these SDR records from the BMC and shows the correct
sensor data on these platforms. (BZ#671059, BZ#749796)

* Prior to this update, the exit code of the 'ipmitool -o list' option
was not set correctly. As a consequence, 'ipmitool -o list' always
returned the value 1 instead of the expected value 0. This update
modifies the underlying code to return the value 0 as expected.
(BZ#740780)

* Prior to this update, the 'ipmi' service init script did not specify
the full path to the '/sbin/lsmod' and '/sbin/modprobe' system
utilities. As a consequence, the init script failed when it was
executed if PATH did not point to /sbin, for example, when running
'sudo /etc/init.d/ipmi'. This update modifies the init script so that
it now contains the full path to lsmod and modrpobe. Now, it can be
executed with sudo. (BZ#829705)

* Prior to this update, the ipmitool man page did not list the '-b',
'-B', '-l' and '-T' options. In this update, these options are
documented in the ipmitool man page. (BZ#846596)

This update also adds the following enhancement :

* Updates to the Dell-specific IPMI extension: A new vFlash command,
which allows users to display information about extended SD cards; a
new setled command, which allows users to display the backplane LED
status; improved error descriptions; added support for new hardware;
and updated documentation of the ipmitool delloem commands in the
ipmitool manual page. (BZ#797050)

All users of OpenIPMI are advised to upgrade to these updated
packages, which contain backported patches to correct these issues and
add this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-January/003196.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openipmi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:OpenIPMI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:OpenIPMI-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:OpenIPMI-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:OpenIPMI-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:OpenIPMI-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:OpenIPMI-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:OpenIPMI-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/12");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"OpenIPMI-2.0.16-16.el5")) flag++;
if (rpm_check(release:"EL5", reference:"OpenIPMI-devel-2.0.16-16.el5")) flag++;
if (rpm_check(release:"EL5", reference:"OpenIPMI-gui-2.0.16-16.el5")) flag++;
if (rpm_check(release:"EL5", reference:"OpenIPMI-libs-2.0.16-16.el5")) flag++;
if (rpm_check(release:"EL5", reference:"OpenIPMI-perl-2.0.16-16.el5")) flag++;
if (rpm_check(release:"EL5", reference:"OpenIPMI-python-2.0.16-16.el5")) flag++;
if (rpm_check(release:"EL5", reference:"OpenIPMI-tools-2.0.16-16.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenIPMI / OpenIPMI-devel / OpenIPMI-gui / OpenIPMI-libs / etc");
}
