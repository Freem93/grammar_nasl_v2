#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0599. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54596);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2011-0010");
  script_bugtraq_id(45774);
  script_xref(name:"RHSA", value:"2011:0599");

  script_name(english:"RHEL 6 : sudo (RHSA-2011:0599)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sudo package that fixes one security issue and several bugs
is now available for Red Hat Enterprise Linux 6.

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

This update also fixes the following bugs :

* When the '/etc/sudoers' file contained entries with multiple hosts,
running the 'sudo -l' command incorrectly reported that a certain user
does not have permissions to use sudo on the system. With this update,
running the 'sudo -l' command now produces the correct output.
(BZ#603823)

* Prior to this update, the manual page for sudoers.ldap was not
installed, even though it contains important information on how to set
up an LDAP (Lightweight Directory Access Protocol) sudoers source, and
other documents refer to it. With this update, the manual page is now
properly included in the package. Additionally, various POD files have
been removed from the package, as they are required for build purposes
only. (BZ#634159)

* The previous version of sudo did not use the same location for the
LDAP configuration files as the nss_ldap package. This has been fixed
and sudo now looks for these files in the same location as the
nss_ldap package. (BZ#652726)

* When a file was edited using the 'sudo -e file' or the 'sudoedit
file' command, the editor being executed for this task was logged only
as 'sudoedit'. With this update, the full path to the executable being
used as an editor is now logged (instead of 'sudoedit'). (BZ#665131)

* A comment regarding the 'visiblepw' option of the 'Defaults'
directive has been added to the default '/etc/sudoers' file to clarify
its usage. (BZ#688640)

* This erratum upgrades sudo to upstream version 1.7.4p5, which
provides a number of bug fixes and enhancements over the previous
version. (BZ#615087)

All users of sudo are advised to upgrade to this updated package,
which resolves these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0599.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sudo and / or sudo-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0599";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sudo-1.7.4p5-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sudo-1.7.4p5-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sudo-1.7.4p5-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sudo-debuginfo-1.7.4p5-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sudo-debuginfo-1.7.4p5-5.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sudo-debuginfo-1.7.4p5-5.el6")) flag++;

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
