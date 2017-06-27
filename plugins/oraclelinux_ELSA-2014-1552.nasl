#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1552 and 
# Oracle Linux Security Advisory ELSA-2014-1552 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(78526);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/07 20:57:51 $");

  script_cve_id("CVE-2014-2532", "CVE-2014-2653");
  script_bugtraq_id(66355, 66459);
  script_osvdb_id(104578, 105011);
  script_xref(name:"RHSA", value:"2014:1552");

  script_name(english:"Oracle Linux 6 : openssh (ELSA-2014-1552)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:1552 :

Updated openssh packages that fix two security issues, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

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

It was found that OpenSSH did not properly handle certain AcceptEnv
parameter values with wildcard characters. A remote attacker could use
this flaw to bypass intended environment variable restrictions.
(CVE-2014-2532)

This update also fixes the following bugs :

* Based on the SP800-131A information security standard, the
generation of a digital signature using the Digital Signature
Algorithm (DSA) with the key size of 1024 bits and RSA with the key
size of less than 2048 bits is disallowed after the year 2013. After
this update, ssh-keygen no longer generates keys with less than 2048
bits in FIPS mode. However, the sshd service accepts keys of size 1024
bits as well as larger keys for compatibility reasons. (BZ#993580)

* Previously, the openssh utility incorrectly set the oom_adj value to
-17 for all of its children processes. This behavior was incorrect
because the children processes were supposed to have this value set to
0. This update applies a patch to fix this bug and oom_adj is now
properly set to 0 for all children processes as expected. (BZ#1010429)

* Previously, if the sshd service failed to verify the checksum of an
installed FIPS module using the fipscheck library, the information
about this failure was only provided at the standard error output of
sshd. As a consequence, the user could not notice this message and be
uninformed when a system had not been properly configured for FIPS
mode. To fix this bug, this behavior has been changed and sshd now
sends such messages via the syslog service. (BZ#1020803)

* When keys provided by the pkcs11 library were removed from the ssh
agent using the 'ssh-add -e' command, the user was prompted to enter a
PIN. With this update, a patch has been applied to allow the user to
remove the keys provided by pkcs11 without the PIN. (BZ#1042519)

In addition, this update adds the following enhancements :

* With this update, ControlPersist has been added to OpenSSH. The
option in conjunction with the ControlMaster configuration directive
specifies that the master connection remains open in the background
after the initial client connection has been closed. (BZ#953088)

* When the sshd daemon is configured to force the internal SFTP
session, and the user attempts to use a connection other than SFTP,
the appropriate message is logged to the /var/log/secure file.
(BZ#997377)

* Support for Elliptic Curve Cryptography modes for key exchange
(ECDH) and host user keys (ECDSA) as specified by RFC5656 has been
added to the openssh packages. However, they are not enabled by
default and the user has to enable them manually. For more information
on how to configure ECDSA and ECDH with OpenSSH, see:
https://access.redhat.com/solutions/711953 (BZ#1028335)

All openssh users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-October/004529.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"openssh-5.3p1-104.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-askpass-5.3p1-104.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-clients-5.3p1-104.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-ldap-5.3p1-104.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-server-5.3p1-104.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pam_ssh_agent_auth-0.9.3-104.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-clients / openssh-ldap / etc");
}
