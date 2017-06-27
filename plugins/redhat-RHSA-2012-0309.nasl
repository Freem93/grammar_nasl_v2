#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0309. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58063);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2011-0010");
  script_xref(name:"RHSA", value:"2012:0309");

  script_name(english:"RHEL 5 : sudo (RHSA-2012:0309)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sudo package that fixes one security issue and various bugs
is now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The sudo (superuser do) utility allows system administrators to give
certain users the ability to run commands as root.

A flaw was found in the sudo password checking logic. In
configurations where the sudoers settings allowed a user to run a
command using sudo with only the group ID changed, sudo failed to
prompt for the user's password before running the specified command
with the elevated group privileges. (CVE-2011-0010)

In addition, this update fixes the following bugs :

* A NULL pointer dereference bug caused the sudo utility to terminate
unexpectedly with a segmentation fault. This happened if the utility
was run with the -g option and configured not to demand the password
from the user who ran the sudo utility. With this update, the code has
been modified and the problem no longer occurs. (BZ#673072)

* The sudo utility failed to load sudoers from an LDAP (Lightweight
Directory Access Protocol) server after the sudo tool was upgraded.
This happened because the upgraded nsswitch.conf file did not contain
the instruction to search for sudoers on the LDAP server. This update
adds the lost instruction to /etc/nsswitch.conf and the system
searches for sources of sudoers on the local file system and then on
LDAP, if applicable. (BZ#617061)

* The sudo tool interpreted a Runas alias specifying a group
incorrectly as a user alias and the alias seemed to be ignored. With
this update, the code for interpreting such aliases has been modified
and the Runas group aliases are honored as expected. (BZ#627543)

* Prior to this update, sudo did not parse comment characters (#) in
the ldap.conf file correctly and could fail to work. With this update,
parsing of the LDAP configuration file has been modified and the
comment characters are parsed correctly. (BZ#750318)

* The sudo utility formats its output to fit the width of the terminal
window. However, this behavior is undesirable if the output is
redirected through a pipeline. With this update, the output formatting
is not applied in the scenario described. (BZ#697111)

* Previously, the sudo utility performed Security-Enhanced Linux
(SELinux) related initialization after switching to an unprivileged
user. This prevented the correct setup of the SELinux environment
before executing the specified command and could potentially cause an
access denial. The bug has been fixed by backporting the SELinux
related code and the execution model from a newer version of sudo.
(BZ#477185)

* On execv(3) function failure, the sudo tool executed an auditing
call before reporting the failure. The call reset the error state and,
consequently, the tool incorrectly reported that the command
succeeded. With this update, the code has been modified and the
problem no longer occurs. (BZ#673157)

All users of sudo are advised to upgrade to this updated package,
which resolves these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0309.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sudo and / or sudo-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:0309";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sudo-1.7.2p1-13.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sudo-1.7.2p1-13.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sudo-1.7.2p1-13.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sudo-debuginfo-1.7.2p1-13.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sudo-debuginfo-1.7.2p1-13.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sudo-debuginfo-1.7.2p1-13.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo / sudo-debuginfo");
  }
}
