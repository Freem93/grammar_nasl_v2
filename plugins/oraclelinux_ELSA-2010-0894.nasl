#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0894 and 
# Oracle Linux Security Advisory ELSA-2010-0894 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68146);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/14 15:20:33 $");

  script_cve_id("CVE-2010-4170", "CVE-2010-4171");
  script_osvdb_id(69489, 69490);
  script_xref(name:"RHSA", value:"2010:0894");

  script_name(english:"Oracle Linux 5 / 6 : systemtap (ELSA-2010-0894)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0894 :

Updated systemtap packages that fix two security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

SystemTap is an instrumentation system for systems running the Linux
kernel, version 2.6. Developers can write scripts to collect data on
the operation of the system. staprun, the SystemTap runtime tool, is
used for managing SystemTap kernel modules (for example, loading
them).

It was discovered that staprun did not properly sanitize the
environment before executing the modprobe command to load an
additional kernel module. A local, unprivileged user could use this
flaw to escalate their privileges. (CVE-2010-4170)

It was discovered that staprun did not check if the module to be
unloaded was previously loaded by SystemTap. A local, unprivileged
user could use this flaw to unload an arbitrary kernel module that was
not in use. (CVE-2010-4171)

Note: After installing this update, users already in the stapdev group
must be added to the stapusr group in order to be able to run the
staprun tool.

Red Hat would like to thank Tavis Ormandy for reporting these issues.

SystemTap users should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-November/001742.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-February/001840.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemtap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemtap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemtap-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemtap-grapher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemtap-initscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemtap-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemtap-sdt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemtap-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemtap-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/17");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"systemtap-1.1-3.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"systemtap-client-1.1-3.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"systemtap-initscript-1.1-3.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"systemtap-runtime-1.1-3.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"systemtap-sdt-devel-1.1-3.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"systemtap-server-1.1-3.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"systemtap-testsuite-1.1-3.el5_5.3")) flag++;

if (rpm_check(release:"EL6", reference:"systemtap-1.2-11.0.1.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"systemtap-client-1.2-11.0.1.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"systemtap-grapher-1.2-11.0.1.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"systemtap-initscript-1.2-11.0.1.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"systemtap-runtime-1.2-11.0.1.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"systemtap-sdt-devel-1.2-11.0.1.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"systemtap-server-1.2-11.0.1.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"systemtap-testsuite-1.2-11.0.1.el6_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemtap / systemtap-client / systemtap-grapher / etc");
}
