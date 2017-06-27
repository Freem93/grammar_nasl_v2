#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0425 and 
# Oracle Linux Security Advisory ELSA-2015-0425 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81725);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/06 17:02:16 $");

  script_cve_id("CVE-2014-2653", "CVE-2014-9278");
  script_bugtraq_id(66459, 71420);
  script_osvdb_id(105011, 115752);
  script_xref(name:"RHSA", value:"2015:0425");

  script_name(english:"Oracle Linux 7 : openssh (ELSA-2015-0425)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0425 :

Updated openssh packages that fix two security issues, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSH is OpenBSD's SSH (Secure Shell) protocol implementation. These
packages include the core files necessary for both the OpenSSH client
and server.

It was discovered that OpenSSH clients did not correctly verify DNS
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
previous version. (BZ#1059667)

Bug fixes :

* An existing /dev/log socket is needed when logging using the syslog
utility, which is not possible for all chroot environments based on
the user's home directories. As a consequence, the sftp commands were
not logged in the chroot setup without /dev/log in the internal sftp
subsystem. With this update, openssh has been enhanced to detect
whether /dev/log exists. If /dev/log does not exist, processes in the
chroot environment use their master processes for logging.
(BZ#1083482)

* The buffer size for a host name was limited to 64 bytes. As a
consequence, when a host name was 64 bytes long or longer, the
ssh-keygen utility failed. The buffer size has been increased to fix
this bug, and ssh-keygen no longer fails in the described situation.
(BZ#1097665)

* Non-ASCII characters have been replaced by their octal
representations in banner messages in order to prevent terminal
re-programming attacks. Consequently, banners containing UTF-8 strings
were not correctly displayed in a client. With this update, banner
messages are processed according to RFC 3454, control characters have
been removed, and banners containing UTF-8 strings are now displayed
correctly. (BZ#1104662)

* Red Hat Enterprise Linux uses persistent Kerberos credential caches,
which are shared between sessions. Previously, the
GSSAPICleanupCredentials option was set to 'yes' by default.
Consequently, removing a Kerberos cache on logout could remove
unrelated credentials of other sessions, which could make the system
unusable. To fix this bug, GSSAPICleanupCredentials is set by default
to 'no'. (BZ#1134447)

* Access permissions for the /etc/ssh/moduli file were set to 0600,
which was unnecessarily strict. With this update, the permissions for
/etc/ssh/moduli have been changed to 0644 to make the access to the
file easier. (BZ#1134448)

* Due to the KRB5CCNAME variable being truncated, the Kerberos ticket
cache was not found after login using a Kerberos-enabled SSH
connection. The underlying source code has been modified to fix this
bug, and Kerberos authentication works as expected in the described
situation. (BZ#1161173)

Enhancements :

* When the sshd daemon is configured to force the internal SFTP
session, a connection other then SFTP is used, the appropriate message
is logged to the /var/log/secure file. (BZ#1130198)

* The sshd-keygen service was run using the
'ExecStartPre=-/usr/sbin/sshd-keygen' option in the sshd.service unit
file. With this update, the separate sshd-keygen.service unit file has
been added, and sshd.service has been adjusted to require
sshd-keygen.service. (BZ#1134997)

Users of openssh are advised to upgrade to these updated packages,
which correct these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004875.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-keycat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-server-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-6.6.1p1-11.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-askpass-6.6.1p1-11.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-clients-6.6.1p1-11.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-keycat-6.6.1p1-11.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-ldap-6.6.1p1-11.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-server-6.6.1p1-11.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssh-server-sysvinit-6.6.1p1-11.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pam_ssh_agent_auth-0.9.3-9.11.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-clients / openssh-keycat / etc");
}
