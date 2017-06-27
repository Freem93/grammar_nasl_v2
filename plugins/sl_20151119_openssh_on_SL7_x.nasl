#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87567);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_cve_id("CVE-2015-5600", "CVE-2015-6563", "CVE-2015-6564");

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
"A flaw was found in the way OpenSSH handled PAM authentication when
using privilege separation. An attacker with valid credentials on the
system and able to fully compromise a non-privileged
pre-authentication process using a different flaw could use this flaw
to authenticate as other users. (CVE-2015-6563)

A use-after-free flaw was found in OpenSSH. An attacker able to fully
compromise a non-privileged pre-authentication process using a
different flaw could possibly cause sshd to crash or execute arbitrary
code with root privileges. (CVE-2015-6564)

It was discovered that the OpenSSH sshd daemon did not check the list
of keyboard-interactive authentication methods for duplicates. A
remote attacker could use this flaw to bypass the MaxAuthTries limit,
making it easier to perform password guessing attacks. (CVE-2015-5600)

It was found that the OpenSSH ssh-agent, a program to hold private
keys used for public key authentication, was vulnerable to password
guessing attacks. An attacker able to connect to the agent could use
this flaw to conduct a brute-force attack to unlock keys in the
ssh-agent.

This update fixes the following bugs :

  - Previously, the sshd_config(5) man page was misleading
    and could thus confuse the user. This update improves
    the man page text to clearly describe the AllowGroups
    feature.

  - The limit for the function for restricting the number of
    files listed using the wildcard character (*) that
    prevents the Denial of Service (DoS) for both server and
    client was previously set too low. Consequently, the
    user reaching the limit was prevented from listing a
    directory with a large number of files over Secure File
    Transfer Protocol (SFTP). This update increases the
    aforementioned limit, thus fixing this bug.

  - When the ForceCommand option with a pseudoterminal was
    used and the MaxSession option was set to '2',
    multiplexed SSH connections did not work as expected.
    After the user attempted to open a second multiplexed
    connection, the attempt failed if the first connection
    was still open. This update modifies OpenSSH to issue
    only one audit message per session, and the user is thus
    able to open two multiplexed connections in this
    situation.

  - The ssh-copy-id utility failed if the account on the
    remote server did not use an sh-like shell. Remote
    commands have been modified to run in an sh-like shell,
    and ssh-copy-id now works also with non-sh-like shells.

  - Due to a race condition between auditing messages and
    answers when using ControlMaster multiplexing, one
    session in the shared connection randomly and
    unexpectedly exited the connection. This update fixes
    the race condition in the auditing code, and
    multiplexing connections now work as expected even with
    a number of sessions created at once.

In addition, this update adds the following enhancements :

  - As not all Lightweight Directory Access Protocol (LDAP)
    servers possess a default schema, as expected by the
    ssh-ldap-helper program, this update provides the user
    with an ability to adjust the LDAP query to get public
    keys from servers with a different schema, while the
    default functionality stays untouched.

  - With this enhancement update, the administrator is able
    to set permissions for files uploaded using Secure File
    Transfer Protocol (SFTP).

  - This update provides the LDAP schema in LDAP Data
    Interchange Format (LDIF) format as a complement to the
    old schema previously accepted by OpenLDAP.

  - With this update, the user can selectively disable the
    Generic Security Services API (GSSAPI) key exchange
    algorithms as any normal key exchange."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=13856
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?baf1505f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-askpass-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-clients-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-debuginfo-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-keycat-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-ldap-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-server-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openssh-server-sysvinit-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pam_ssh_agent_auth-0.9.3-9.22.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
