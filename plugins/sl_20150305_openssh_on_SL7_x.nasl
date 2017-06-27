#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82258);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/26 13:38:48 $");

  script_cve_id("CVE-2014-2653", "CVE-2014-9278");

  script_name(english:"Scientific Linux Security Update : openssh on SL7.x x86_64");
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
"It was discovered that OpenSSH clients did not correctly verify DNS
SSHFP records. A malicious server could use this flaw to force a
connecting client to skip the DNS SSHFP record check and require the
user to perform manual host verification of the DNS SSHFP record.
(CVE-2014-2653)

It was found that when OpenSSH was used in a Kerberos environment,
remote authenticated users were allowed to log in as a different user
if they were listed in the ~/.k5users file of that user, potentially
bypassing intended authentication restrictions. (CVE-2014-9278)

The openssh packages have been upgraded to upstream version 6.6.1,
which provides a number of bug fixes and enhancements over the
previous version.

Bug fixes :

  - An existing /dev/log socket is needed when logging using
    the syslog utility, which is not possible for all chroot
    environments based on the user's home directories. As a
    consequence, the sftp commands were not logged in the
    chroot setup without /dev/log in the internal sftp
    subsystem. With this update, openssh has been enhanced
    to detect whether /dev/log exists. If /dev/log does not
    exist, processes in the chroot environment use their
    master processes for logging.

  - The buffer size for a host name was limited to 64 bytes.
    As a consequence, when a host name was 64 bytes long or
    longer, the ssh-keygen utility failed. The buffer size
    has been increased to fix this bug, and ssh-keygen no
    longer fails in the described situation.

  - Non-ASCII characters have been replaced by their octal
    representations in banner messages in order to prevent
    terminal re-programming attacks. Consequently, banners
    containing UTF-8 strings were not correctly displayed in
    a client. With this update, banner messages are
    processed according to RFC 3454, control characters have
    been removed, and banners containing UTF-8 strings are
    now displayed correctly.

  - Scientific Linux uses persistent Kerberos credential
    caches, which are shared between sessions. Previously,
    the GSSAPICleanupCredentials option was set to 'yes' by
    default. Consequently, removing a Kerberos cache on
    logout could remove unrelated credentials of other
    sessions, which could make the system unusable. To fix
    this bug, GSSAPICleanupCredentials is set by default to
    'no'.

  - Access permissions for the /etc/ssh/moduli file were set
    to 0600, which was unnecessarily strict. With this
    update, the permissions for /etc/ssh/moduli have been
    changed to 0644 to make the access to the file easier.

  - Due to the KRB5CCNAME variable being truncated, the
    Kerberos ticket cache was not found after login using a
    Kerberos-enabled SSH connection. The underlying source
    code has been modified to fix this bug, and Kerberos
    authentication works as expected in the described
    situation.

Enhancements :

  - When the sshd daemon is configured to force the internal
    SFTP session, a connection other then SFTP is used, the
    appropriate message is logged to the /var/log/secure
    file.

  - The sshd-keygen service was run using the
    'ExecStartPre=-/usr/sbin/sshd- keygen' option in the
    sshd.service unit file. With this update, the separate
    sshd-keygen.service unit file has been added, and
    sshd.service has been adjusted to require
    sshd-keygen.service."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=3247
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7cd45b81"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-6.6.1p1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-askpass-6.6.1p1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-clients-6.6.1p1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-debuginfo-6.6.1p1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-keycat-6.6.1p1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-ldap-6.6.1p1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-server-6.6.1p1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-server-sysvinit-6.6.1p1-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pam_ssh_agent_auth-0.9.3-9.11.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
