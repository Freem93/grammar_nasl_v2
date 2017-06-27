#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0884 and 
# Oracle Linux Security Advisory ELSA-2012-0884 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68558);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/01 17:07:15 $");

  script_cve_id("CVE-2011-5000");
  script_osvdb_id(81500);
  script_xref(name:"RHSA", value:"2012:0884");

  script_name(english:"Oracle Linux 6 : openssh (ELSA-2012-0884)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0884 :

Updated openssh packages that fix one security issue, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

OpenSSH is OpenBSD's Secure Shell (SSH) protocol implementation. These
packages include the core files necessary for the OpenSSH client and
server.

A denial of service flaw was found in the OpenSSH GSSAPI
authentication implementation. A remote, authenticated user could use
this flaw to make the OpenSSH server daemon (sshd) use an excessive
amount of memory, leading to a denial of service. GSSAPI
authentication is enabled by default ('GSSAPIAuthentication yes' in
'/etc/ssh/sshd_config'). (CVE-2011-5000)

These updated openssh packages also provide fixes for the following
bugs :

* SSH X11 forwarding failed if IPv6 was enabled and the parameter
X11UseLocalhost was set to 'no'. Consequently, users could not set X
forwarding. This update fixes sshd and ssh to correctly bind the port
for the IPv6 protocol. As a result, X11 forwarding now works as
expected with IPv6. (BZ#732955)

* The sshd daemon was killed by the OOM killer when running a stress
test. Consequently, a user could not log in. With this update, the
sshd daemon sets its oom_adj value to -17. As a result, sshd is not
chosen by OOM killer and users are able to log in to solve problems
with memory. (BZ#744236)

* If the SSH server is configured with a banner that contains a
backslash character, then the client will escape it with another '\'
character, so it prints double backslashes. An upstream patch has been
applied to correct the problem and the SSH banner is now correctly
displayed. (BZ#809619)

In addition, these updated openssh packages provide the following
enhancements :

* Previously, SSH allowed multiple ways of authentication of which
only one was required for a successful login. SSH can now be set up to
require multiple ways of authentication. For example, logging in to an
SSH-enabled machine requires both a passphrase and a public key to be
entered. The RequiredAuthentications1 and RequiredAuthentications2
options can be configured in the /etc/ssh/sshd_config file to specify
authentications that are required for a successful login. For example,
to set key and password authentication for SSH version 2, type :

echo 'RequiredAuthentications2 publickey,password' >>
/etc/ssh/sshd_config

For more information on the aforementioned /etc/ssh/sshd_config
options, refer to the sshd_config man page. (BZ#657378)

* Previously, OpenSSH could use the Advanced Encryption Standard New
Instructions (AES-NI) instruction set only with the AES Cipher-block
chaining (CBC) cipher. This update adds support for Counter (CTR) mode
encryption in OpenSSH so the AES-NI instruction set can now be used
efficiently also with the AES CTR cipher. (BZ#756929)

* Prior to this update, an unprivileged slave sshd process was run as
the sshd_t context during privilege separation (privsep). sshd_t is
the SELinux context used for running the sshd daemon. Given that the
unprivileged slave process is run under the user's UID, it is fitting
to run this process under the user's SELinux context instead of the
privileged sshd_t context. With this update, the unprivileged slave
process is now run as the user's context instead of the sshd_t context
in accordance with the principle of privilege separation. The
unprivileged process, which might be potentially more sensitive to
security threats, is now run under the user's SELinux context.
(BZ#798241)

Users are advised to upgrade to these updated openssh packages, which
contain backported patches to resolve these issues and add these
enhancements. After installing this update, the OpenSSH server daemon
(sshd) will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-July/002909.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL6", reference:"openssh-5.3p1-81.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-askpass-5.3p1-81.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-clients-5.3p1-81.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-ldap-5.3p1-81.el6")) flag++;
if (rpm_check(release:"EL6", reference:"openssh-server-5.3p1-81.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pam_ssh_agent_auth-0.9-81.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-clients / openssh-ldap / etc");
}
