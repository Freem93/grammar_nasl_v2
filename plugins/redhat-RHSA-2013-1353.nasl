#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1353. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70249);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-1775", "CVE-2013-1776", "CVE-2013-2776");
  script_bugtraq_id(58203, 58207);
  script_xref(name:"RHSA", value:"2013:1353");

  script_name(english:"RHEL 5 : sudo (RHSA-2013:1353)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sudo package that fixes multiple security issues and
several bugs is now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The sudo (superuser do) utility allows system administrators to give
certain users the ability to run commands as root.

A flaw was found in the way sudo handled time stamp files. An attacker
able to run code as a local user and with the ability to control the
system clock could possibly gain additional privileges by running
commands that the victim user was allowed to run via sudo, without
knowing the victim's password. (CVE-2013-1775)

It was found that sudo did not properly validate the controlling
terminal device when the tty_tickets option was enabled in the
/etc/sudoers file. An attacker able to run code as a local user could
possibly gain additional privileges by running commands that the
victim user was allowed to run via sudo, without knowing the victim's
password. (CVE-2013-1776, CVE-2013-2776)

This update also fixes the following bugs :

* Due to a bug in the cycle detection algorithm of the visudo utility,
visudo incorrectly evaluated certain alias definitions in the
/etc/sudoers file as cycles. Consequently, a warning message about
undefined aliases appeared. This bug has been fixed, /etc/sudoers is
now parsed correctly by visudo and the warning message no longer
appears. (BZ#849679)

* Previously, the 'sudo -l' command did not parse the /etc/sudoers
file correctly if it contained an Active Directory (AD) group. The
file was parsed only up to the first AD group information and then the
parsing failed with the following message :

sudo: unable to cache group ADDOM\admingroup, already exists

With this update, the underlying code has been modified and 'sudo -l'
now parses /etc/sudoers containing AD groups correctly. (BZ#855836)

* Previously, the sudo utility did not escape the backslash characters
contained in user names properly. Consequently, if a system used sudo
integrated with LDAP or Active Directory (AD) as the primary
authentication mechanism, users were not able to authenticate on that
system. With this update, sudo has been modified to process LDAP and
AD names correctly and the authentication process now works as
expected. (BZ#869287)

* Prior to this update, the 'visudo -s (strict)' command incorrectly
parsed certain alias definitions. Consequently, an error message was
issued. The bug has been fixed, and parsing errors no longer occur
when using 'visudo -s'. (BZ#905624)

All sudo users are advised to upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1775.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1353.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sudo and / or sudo-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X Sudo Password Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:1353";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sudo-1.7.2p1-28.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sudo-1.7.2p1-28.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sudo-1.7.2p1-28.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sudo-debuginfo-1.7.2p1-28.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sudo-debuginfo-1.7.2p1-28.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sudo-debuginfo-1.7.2p1-28.el5")) flag++;

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
