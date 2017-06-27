#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1701. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71017);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-1775", "CVE-2013-2776", "CVE-2013-2777");
  script_bugtraq_id(58203, 58207);
  script_osvdb_id(90661, 90677);
  script_xref(name:"RHSA", value:"2013:1701");

  script_name(english:"RHEL 6 : sudo (RHSA-2013:1701)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sudo package that fixes two security issues, several bugs,
and adds two enhancements is now available for Red Hat Enterprise
Linux 6.

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
password. (CVE-2013-2776, CVE-2013-2777)

This update also fixes the following bugs :

* Previously, sudo did not support netgroup filtering for sources from
the System Security Services Daemon (SSSD). Consequently, SSSD rules
were applied to all users even when they did not belong to the
specified netgroup. With this update, netgroup filtering for SSSD
sources has been implemented. As a result, rules with a netgroup
specification are applied only to users that are part of the netgroup.
(BZ#880150)

* When the sudo utility set up the environment in which it ran a
command, it reset the value of the RLIMIT_NPROC resource limit to the
parent's value of this limit if both the soft (current) and hard
(maximum) values of RLIMIT_NPROC were not limited. An upstream patch
has been provided to address this bug and RLIMIT_NPROC can now be set
to 'unlimited'. (BZ#947276)

* Due to the refactoring of the sudo code by upstream, the SUDO_USER
variable that stores the name of the user running the sudo command was
not logged to the /var/log/secure file as before. Consequently, user
name 'root' was always recorded instead of the real user name. With
this update, the previous behavior of sudo has been restored. As a
result, the expected user name is now written to /var/log/secure.
(BZ#973228)

* Due to an error in a loop condition in sudo's rule listing code, a
buffer overflow could have occurred in certain cases. This condition
has been fixed and the buffer overflow no longer occurs. (BZ#994626)

In addition, this update adds the following enhancements :

* With this update, sudo has been modified to send debug messages
about netgroup matching to the debug log. These messages should
provide better understanding of how sudo matches netgroup database
records with values from the running system and what the values are
exactly. (BZ#848111)

* With this update, sudo has been modified to accept the ipa_hostname
value from the /etc/sssd/sssd.conf configuration file when matching
netgroups. (BZ#853542)

All sudo users are advised to upgrade to this updated package, which
contains backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1775.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2777.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1701.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sudo, sudo-debuginfo and / or sudo-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X Sudo Password Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sudo-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/21");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1701";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sudo-1.8.6p3-12.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sudo-1.8.6p3-12.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sudo-1.8.6p3-12.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sudo-debuginfo-1.8.6p3-12.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sudo-devel-1.8.6p3-12.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo / sudo-debuginfo / sudo-devel");
  }
}
