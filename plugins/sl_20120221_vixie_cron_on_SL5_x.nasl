#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61273);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2010-0424");

  script_name(english:"Scientific Linux Security Update : vixie-cron on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The vixie-cron package contains the Vixie version of cron. Cron is a
standard UNIX daemon that runs specified programs at scheduled times.
The vixie-cron package adds improved security and more powerful
configuration options to the standard version of cron.

A race condition was found in the way the crontab program performed
file time stamp updates on a temporary file created when editing a
user crontab file. A local attacker could use this flaw to change the
modification time of arbitrary system files via a symbolic link
attack. (CVE-2010-0424)

This update also fixes the following bugs :

  - Cron jobs of users with home directories mounted on a
    Lightweight Directory Access Protocol (LDAP) server or
    Network File System (NFS) were often refused because
    jobs were marked as orphaned (typically due to a
    temporary NSS lookup failure, when NIS and LDAP servers
    were unreachable). With this update, a database of
    orphans is created, and cron jobs are performed as
    expected.

  - Previously, cron did not log any errors if a cron job
    file located in the /etc/cron.d/ directory contained
    invalid entries. An upstream patch has been applied to
    address this problem and invalid entries in the cron job
    files now produce warning messages.

  - Previously, the '@reboot' crontab macro incorrectly ran
    jobs when the crond daemon was restarted. If the user
    used the macro on multiple machines, all entries with
    the '@reboot' option were executed every time the crond
    daemon was restarted. With this update, jobs are
    executed only when the machine is rebooted.

  - The crontab utility is now compiled as a
    position-independent executable (PIE), which enhances
    the security of the system.

  - When the parent crond daemon was stopped, but a child
    crond daemon was running (executing a program), the
    'service crond status' command incorrectly reported that
    crond was running. The source code has been modified,
    and the 'service crond status' command now correctly
    reports that crond is stopped.

  - According to the pam(8) manual page, the cron daemon,
    crond, supports access control with PAM (Pluggable
    Authentication Module). However, the PAM configuration
    file for crond did not export environment variables
    correctly and, consequently, setting PAM variables via
    cron did not work. This update includes a corrected
    /etc/pam.d/crond file that exports environment variables
    correctly. Setting pam variables via cron now works as
    documented in the pam(8) manual page.

  - Previously, the mcstransd daemon modified labels for the
    crond daemon. When the crond daemon attempted to use the
    modified label and mcstransd was not running, crond used
    an incorrect label. Consequently, Security-Enhanced
    Linux (SELinux) denials filled up the cron log, no jobs
    were executed, and crond had to be restarted. With this
    update, both mcstransd and crond use raw SELinux labels,
    which prevents the problem.

  - Previously, the crontab(1) and cron(8) manual pages
    contained multiple typographical errors. This update
    fixes those errors.

In addition, this update adds the following enhancement :

  - Previously, the crontab utility did not use the
    Pluggable Authentication Module (PAM) for verification
    of users. As a consequence, a user could access crontab
    even if access had been restricted (usually by being
    denied in the access.conf file). With this update,
    crontab returns an error message that the user is not
    allowed to access crontab because of PAM configuration.

All vixie-cron users should upgrade to this updated package, which
resolves these issues and adds this enhancement."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=2788
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07ba50c0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vixie-cron and / or vixie-cron-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"vixie-cron-4.1-81.el5")) flag++;
if (rpm_check(release:"SL5", reference:"vixie-cron-debuginfo-4.1-81.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
