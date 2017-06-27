#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64954);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/03/01 11:58:42 $");

  script_cve_id("CVE-2012-5536");

  script_name(english:"Scientific Linux Security Update : openssh on SL6.x i386/x86_64");
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
"Due to the way the pam_ssh_agent_auth PAM module was built in
Scientific Linux 6, the glibc's error() function was called rather
than the intended error() function in pam_ssh_agent_auth to report
errors. As these two functions expect different arguments, it was
possible for an attacker to cause an application using
pam_ssh_agent_auth to crash, disclose portions of its memory or,
potentially, execute arbitrary code. (CVE-2012-5536)

Note that the pam_ssh_agent_auth module is not used in Scientific
Linux 6 by default.

This update also fixes the following bugs :

  - All possible options for the new RequiredAuthentications
    directive were not documented in the sshd_config man
    page. This update improves the man page to document all
    the possible options.

  - When stopping one instance of the SSH daemon (sshd), the
    sshd init script (/etc/rc.d/init.d/sshd) stopped all
    sshd processes regardless of the PID of the processes.
    This update improves the init script so that it only
    kills processes with the relevant PID. As a result, the
    init script now works more reliably in a multi-instance
    environment.

  - Due to a regression, the ssh-copy-id command returned an
    exit status code of zero even if there was an error in
    copying the key to a remote host. With this update, a
    patch has been applied and ssh-copy-id now returns a
    non-zero exit code if there is an error in copying the
    SSH certificate to a remote host.

  - When SELinux was disabled on the system, no on-disk
    policy was installed, a user account was used for a
    connection, and no '~/.ssh' configuration was present in
    that user's home directory, the SSH client terminated
    unexpectedly with a segmentation fault when attempting
    to connect to another system. A patch has been provided
    to address this issue and the crashes no longer occur in
    the described scenario.

  - The 'HOWTO' document
    /usr/share/doc/openssh-ldap-5.3p1/HOWTO.ldap-keys
    incorrectly documented the use of the
    AuthorizedKeysCommand directive. This update corrects
    the document.

This update also adds the following enhancements :

  - When attempting to enable SSH for use with a Common
    Access Card (CAC), the ssh-agent utility read all the
    certificates in the card even though only the ID
    certificate was needed. Consequently, if a user entered
    their PIN incorrectly, then the CAC was locked, as a
    match for the PIN was attempted against all three
    certificates. With this update, ssh-add does not try the
    same PIN for every certificate if the PIN fails for the
    first one. As a result, the CAC will not be disabled if
    a user enters their PIN incorrectly.

  - This update adds a 'netcat mode' to SSH. The 'ssh -W
    host:port ...' command connects standard input and
    output (stdio) on a client to a single port on a server.
    As a result, SSH can be used to route connections via
    intermediate servers.

  - Due to a bug, arguments for the RequiredAuthentications2
    directive were not stored in a Match block.
    Consequently, parsing of the config file was not in
    accordance with the man sshd_config documentation. This
    update fixes the bug and users can now use the required
    authentication feature to specify a list of
    authentication methods as expected according to the man
    page.

After installing this update, the OpenSSH server daemon (sshd) will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=4416
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da71c5e4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

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
if (rpm_check(release:"SL6", reference:"openssh-5.3p1-84.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssh-askpass-5.3p1-84.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssh-clients-5.3p1-84.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssh-debuginfo-5.3p1-84.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssh-ldap-5.3p1-84.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssh-server-5.3p1-84.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pam_ssh_agent_auth-0.9.3-84.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
