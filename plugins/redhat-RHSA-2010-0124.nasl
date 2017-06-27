#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0124. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44956);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/04 15:51:46 $");

  script_cve_id("CVE-2009-4273", "CVE-2010-0411");
  script_xref(name:"RHSA", value:"2010:0124");

  script_name(english:"RHEL 5 : systemtap (RHSA-2010:0124)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated systemtap packages that fix two security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

SystemTap is an instrumentation system for systems running the Linux
kernel, version 2.6. Developers can write scripts to collect data on
the operation of the system.

A flaw was found in the SystemTap compile server, stap-server, an
optional component of SystemTap. This server did not adequately
sanitize input provided by the stap-client program, which may allow a
remote user to execute arbitrary shell code with the privileges of the
compile server process, which could possibly be running as the root
user. (CVE-2009-4273)

Note: stap-server is not run by default. It must be started by a user
or administrator.

A buffer overflow flaw was found in SystemTap's tapset __get_argv()
function. If a privileged user ran a SystemTap script that called this
function, a local, unprivileged user could, while that script is still
running, trigger this flaw and cause memory corruption by running a
command with a large argument list, which may lead to a system crash
or, potentially, arbitrary code execution with root privileges.
(CVE-2010-0411)

Note: SystemTap scripts that call __get_argv(), being a privileged
function, can only be executed by the root user or users in the
stapdev group. As well, if such a script was compiled and installed by
root, users in the stapusr group would also be able to execute it.

SystemTap users should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-4273.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0411.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0124.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-initscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-sdt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:systemtap-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0124";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"systemtap-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"systemtap-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"systemtap-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"systemtap-client-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"systemtap-client-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"systemtap-client-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"systemtap-initscript-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"systemtap-initscript-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"systemtap-initscript-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"systemtap-runtime-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"systemtap-runtime-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"systemtap-runtime-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", reference:"systemtap-sdt-devel-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"systemtap-server-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"systemtap-server-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"systemtap-server-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"systemtap-testsuite-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"systemtap-testsuite-0.9.7-5.el5_4.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"systemtap-testsuite-0.9.7-5.el5_4.3")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemtap / systemtap-client / systemtap-initscript / etc");
  }
}
