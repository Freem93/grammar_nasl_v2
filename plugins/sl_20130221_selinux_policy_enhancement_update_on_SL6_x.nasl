#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64959);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/03/01 11:58:42 $");

  script_name(english:"Scientific Linux Security Update : selinux-policy enhancement update on SL6.x i386/x86_64");
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
"This update adds the following enhancements :

  - With the Multi-Level Security (MLS) SELinux policy
    enabled, a user created with an SELinux MLS level could
    not login to the system through an |SSH| client. The
    SELinux policy rules have been updated to allow the user
    to log in to the system in the described scenario.

  - When SELinux was in enforcing mode, an |OpenMPI| job,
    parallel universe in Red Hat Enterprise Linux MRG Grid,
    failed and was unable to access files in the
    |/var/lib/condor/execute/| directory. New SELinux policy
    rules have been added for |OpenMPI| jobs to allow a job
    to access files in this directory.

  - Due to a regression, the root user was able to log in
    when the |ssh_sysadm_login| variable was set to |OFF| in
    MLS. To fix this bug, the |ssh_sysadm_login| SELinux
    boolean has been corrected to prevent the root user to
    log in when this variable is set to |OFF|.

  - Previously, |cron| daemon jobs were set to run in the
    |cronjob_t| domain when the SELinux MLS policy was
    enabled. As a consequence, users could not run their
    |cron| jobs. The relevant policy rules have been
    modified and |cron| jobs now run in the user domain,
    thus fixing this bug.

  - With SELinux in enforcing mode, during automatic testing
    of Red Hat Enterprise Linux in FIPS mode, PAM (Pluggable
    Authentication Modules) attempted to run prelink on the
    |/sbin/unix_chkpwd| file to verify its hash.
    Consequently, users could not log in to the system. The
    appropriate SELinux policy rules have been updated and a
    FIPS mode boolean has been added to resolve this bug.

  - When the krb5 package was upgraded to version
    1.9-33.el6_3.3 and Identity Management or FreeIPA was
    used, an attempt to start the |named| daemon terminated
    unexpectedly in enforcing mode. This update adapts the
    relevant SELinux policy to make sure the |named| daemon
    can be started in the described scenario.

  - Previously, the |libselinux| library did not support
    setting the context based on the contents of
    |/etc/selinux/targeted/logins/$username/| directories.
    Consequently, central management of SELinux limits did
    not work properly. With this update, the
    |/etc/selinux/targeted/logins/| directory is now handled
    by the selinux-policy packages as expected.

  - In its current version, the |SSSD| daemon writes SELinux
    configuration files into the
    |/etc/selinux/<policy>/logins/| directory. The SELinux
    PAM module then uses this information to set the correct
    context for a remote user trying to log in. Due to a
    missing policy for this feature, |SSSD| could not write
    into this directory. With this update, a new security
    context for |/etc/selinux/<[policy]/logins/| has been
    added together with appropriate SELinux policy rules.

  - With SELinux in enforcing mode, the |saslauthd| daemon
    process could not work properly if the |MECH=shadow|
    option was specified in the |/etc/sysconfig/saslauthd|
    file. This update fixes the relevant SELinux policy
    rules and allows |saslauthd| to use the |MECH=shadow|
    configuration option.

  - When the |MAILDIR=$HOME/Maildir| option was enabled
    either in the |/etc/procmailrc| or in |dovecot|
    configuration files, the |procmail| and |dovecot|
    services were not able to access a Maildir directory
    located in the home directory. This update fixes
    relevant SELinux policy rules to allow the
    |procmail|/|dovecot| service to read the configured
    |MAILDIR| option in |/etc/procmailrc|.

  - When the |vsftpd| daemon is being stopped, it terminates
    all child |vsftpd| processes by sending the SIGTERM
    signal to them. When the parent process dies, the child
    process gets the SIGTERM signal. Previously, this signal
    was blocked by SELinux. This update fixes the relevant
    SELinux policy rules to allow |vsftpd| to terminate its
    child processes properly.

  - Due to missing SELinux policy rules, the |rsync| daemon,
    which served an automounted home NFS directory, was not
    able to write files in this directory. To fix this bug,
    the |rsync| daemon has been changed into a home manager
    to allow the needed access permissions.

  - Previously, SELinux prevented the puppet master from
    running passenger web application. To fix this bug,
    security context for the Passenger Apache module has
    been updated to reflect latest passenger paths to
    executables to make sure all applications using
    Passenger web applications run with the correct SELinux
    domain.

  - When a user attempted to configure the |rsync| daemon to
    log directly to a specific file, missing SELinux policy
    rules let the user create the log file, but did not
    allow to append to it. With this update, SELinux policy
    rules have been added to allow |rsync| to append to a
    specific log file.

  - When multiple devices were added into the system, udev
    rules restarted ktune services for each new device, so
    there were several restarts in a short time interval.
    The multiple restarts triggered a race condition in the
    kernel which was not easily fixable. Currently, the
    tuned code is modified not to trigger more than one
    restart per 10 seconds and the race condition is
    avoided.

This update has been placed in the security tree to avoid selinux
bugs."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=3762
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c9ed0358"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"selinux-policy-3.7.19-195.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-doc-3.7.19-195.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-minimum-3.7.19-195.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-mls-3.7.19-195.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"selinux-policy-targeted-3.7.19-195.el6_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
