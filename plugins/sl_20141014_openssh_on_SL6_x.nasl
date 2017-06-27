#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(78641);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/19 14:25:12 $");

  script_cve_id("CVE-2014-2532", "CVE-2014-2653");

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
"It was discovered that OpenSSH clients did not correctly verify DNS
SSHFP records. A malicious server could use this flaw to force a
connecting client to skip the DNS SSHFP record check and require the
user to perform manual host verification of the DNS SSHFP record.
(CVE-2014-2653)

It was found that OpenSSH did not properly handle certain AcceptEnv
parameter values with wildcard characters. A remote attacker could use
this flaw to bypass intended environment variable restrictions.
(CVE-2014-2532)

This update also fixes the following bugs :

  - Based on the SP800-131A information security standard,
    the generation of a digital signature using the Digital
    Signature Algorithm (DSA) with the key size of 1024 bits
    and RSA with the key size of less than 2048 bits is
    disallowed after the year 2013. After this update,
    ssh-keygen no longer generates keys with less than 2048
    bits in FIPS mode. However, the sshd service accepts
    keys of size 1024 bits as well as larger keys for
    compatibility reasons.

  - Previously, the openssh utility incorrectly set the
    oom_adj value to -17 for all of its children processes.
    This behavior was incorrect because the children
    processes were supposed to have this value set to 0.
    This update applies a patch to fix this bug and oom_adj
    is now properly set to 0 for all children processes as
    expected.

  - Previously, if the sshd service failed to verify the
    checksum of an installed FIPS module using the fipscheck
    library, the information about this failure was only
    provided at the standard error output of sshd. As a
    consequence, the user could not notice this message and
    be uninformed when a system had not been properly
    configured for FIPS mode. To fix this bug, this behavior
    has been changed and sshd now sends such messages via
    the syslog service.

  - When keys provided by the pkcs11 library were removed
    from the ssh agent using the 'ssh-add -e' command, the
    user was prompted to enter a PIN. With this update, a
    patch has been applied to allow the user to remove the
    keys provided by pkcs11 without the PIN.

In addition, this update adds the following enhancements :

  - With this update, ControlPersist has been added to
    OpenSSH. The option in conjunction with the
    ControlMaster configuration directive specifies that the
    master connection remains open in the background after
    the initial client connection has been closed.

  - When the sshd daemon is configured to force the internal
    SFTP session, and the user attempts to use a connection
    other than SFTP, the appropriate message is logged to
    the /var/log/secure file.

  - Support for Elliptic Curve Cryptography modes for key
    exchange (ECDH) and host user keys (ECDSA) as specified
    by RFC5656 has been added to the openssh packages.
    However, they are not enabled by default and the user
    has to enable them manually."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1410&L=scientific-linux-errata&T=0&P=1694
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d90dcb6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"openssh-5.3p1-104.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssh-askpass-5.3p1-104.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssh-clients-5.3p1-104.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssh-debuginfo-5.3p1-104.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssh-ldap-5.3p1-104.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssh-server-5.3p1-104.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pam_ssh_agent_auth-0.9.3-104.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
