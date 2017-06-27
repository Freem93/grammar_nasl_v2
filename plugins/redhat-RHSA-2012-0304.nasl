#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0304. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58058);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2010-0424");
  script_bugtraq_id(38391);
  script_osvdb_id(62551);
  script_xref(name:"RHSA", value:"2012:0304");

  script_name(english:"RHEL 5 : vixie-cron (RHSA-2012:0304)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated vixie-cron package that fixes one security issue, several
bugs, and adds one enhancement is now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The vixie-cron package contains the Vixie version of cron. Cron is a
standard UNIX daemon that runs specified programs at scheduled times.
The vixie-cron package adds improved security and more powerful
configuration options to the standard version of cron.

A race condition was found in the way the crontab program performed
file time stamp updates on a temporary file created when editing a
user crontab file. A local attacker could use this flaw to change the
modification time of arbitrary system files via a symbolic link
attack. (CVE-2010-0424)

Red Hat would like to thank Dan Rosenberg for reporting this issue.

This update also fixes the following bugs :

* Cron jobs of users with home directories mounted on a Lightweight
Directory Access Protocol (LDAP) server or Network File System (NFS)
were often refused because jobs were marked as orphaned (typically due
to a temporary NSS lookup failure, when NIS and LDAP servers were
unreachable). With this update, a database of orphans is created, and
cron jobs are performed as expected. (BZ#455664)

* Previously, cron did not log any errors if a cron job file located
in the /etc/cron.d/ directory contained invalid entries. An upstream
patch has been applied to address this problem and invalid entries in
the cron job files now produce warning messages. (BZ#460070)

* Previously, the '@reboot' crontab macro incorrectly ran jobs when
the crond daemon was restarted. If the user used the macro on multiple
machines, all entries with the '@reboot' option were executed every
time the crond daemon was restarted. With this update, jobs are
executed only when the machine is rebooted. (BZ#476972)

* The crontab utility is now compiled as a position-independent
executable (PIE), which enhances the security of the system.
(BZ#480930)

* When the parent crond daemon was stopped, but a child crond daemon
was running (executing a program), the 'service crond status' command
incorrectly reported that crond was running. The source code has been
modified, and the 'service crond status' command now correctly reports
that crond is stopped. (BZ#529632)

* According to the pam(8) manual page, the cron daemon, crond,
supports access control with PAM (Pluggable Authentication Module).
However, the PAM configuration file for crond did not export
environment variables correctly and, consequently, setting PAM
variables via cron did not work. This update includes a corrected
/etc/pam.d/crond file that exports environment variables correctly.
Setting pam variables via cron now works as documented in the pam(8)
manual page. (BZ#541189)

* Previously, the mcstransd daemon modified labels for the crond
daemon. When the crond daemon attempted to use the modified label and
mcstransd was not running, crond used an incorrect label.
Consequently, Security-Enhanced Linux (SELinux) denials filled up the
cron log, no jobs were executed, and crond had to be restarted. With
this update, both mcstransd and crond use raw SELinux labels, which
prevents the problem. (BZ#625016)

* Previously, the crontab(1) and cron(8) manual pages contained
multiple typographical errors. This update fixes those errors.
(BZ#699620, BZ#699621)

In addition, this update adds the following enhancement :

* Previously, the crontab utility did not use the Pluggable
Authentication Module (PAM) for verification of users. As a
consequence, a user could access crontab even if access had been
restricted (usually by being denied in the access.conf file). With
this update, crontab returns an error message that the user is not
allowed to access crontab because of PAM configuration. (BZ#249512)

All vixie-cron users should upgrade to this updated package, which
resolves these issues and adds this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0424.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0304.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vixie-cron and / or vixie-cron-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vixie-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vixie-cron-debuginfo");
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
  rhsa = "RHSA-2012:0304";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"vixie-cron-4.1-81.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"vixie-cron-4.1-81.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"vixie-cron-4.1-81.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"vixie-cron-debuginfo-4.1-81.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"vixie-cron-debuginfo-4.1-81.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"vixie-cron-debuginfo-4.1-81.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vixie-cron / vixie-cron-debuginfo");
  }
}
