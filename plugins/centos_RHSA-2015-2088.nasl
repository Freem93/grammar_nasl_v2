#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2088 and 
# CentOS Errata and Security Advisory 2015:2088 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(87128);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/04/28 18:15:07 $");

  script_cve_id("CVE-2015-5600", "CVE-2015-6563", "CVE-2015-6564");
  script_osvdb_id(124938, 126030, 126033);
  script_xref(name:"RHSA", value:"2015:2088");

  script_name(english:"CentOS 7 : openssh (CESA-2015:2088)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix multiple security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSH is OpenBSD's SSH (Secure Shell) protocol implementation. These
packages include the core files necessary for both the OpenSSH client
and server.

A flaw was found in the way OpenSSH handled PAM authentication when
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
ssh-agent. (BZ#1238238)

This update fixes the following bugs :

* Previously, the sshd_config(5) man page was misleading and could
thus confuse the user. This update improves the man page text to
clearly describe the AllowGroups feature. (BZ#1150007)

* The limit for the function for restricting the number of files
listed using the wildcard character (*) that prevents the Denial of
Service (DoS) for both server and client was previously set too low.
Consequently, the user reaching the limit was prevented from listing a
directory with a large number of files over Secure File Transfer
Protocol (SFTP). This update increases the aforementioned limit, thus
fixing this bug. (BZ#1160377)

* When the ForceCommand option with a pseudoterminal was used and the
MaxSession option was set to '2', multiplexed SSH connections did not
work as expected. After the user attempted to open a second
multiplexed connection, the attempt failed if the first connection was
still open. This update modifies OpenSSH to issue only one audit
message per session, and the user is thus able to open two multiplexed
connections in this situation. (BZ#1199112)

* The ssh-copy-id utility failed if the account on the remote server
did not use an sh-like shell. Remote commands have been modified to
run in an sh-like shell, and ssh-copy-id now works also with
non-sh-like shells. (BZ#1201758)

* Due to a race condition between auditing messages and answers when
using ControlMaster multiplexing, one session in the shared connection
randomly and unexpectedly exited the connection. This update fixes the
race condition in the auditing code, and multiplexing connections now
work as expected even with a number of sessions created at once.
(BZ#1240613)

In addition, this update adds the following enhancements :

* As not all Lightweight Directory Access Protocol (LDAP) servers
possess a default schema, as expected by the ssh-ldap-helper program,
this update provides the user with an ability to adjust the LDAP query
to get public keys from servers with a different schema, while the
default functionality stays untouched. (BZ#1201753)

* With this enhancement update, the administrator is able to set
permissions for files uploaded using Secure File Transfer Protocol
(SFTP). (BZ#1197989)

* This update provides the LDAP schema in LDAP Data Interchange Format
(LDIF) format as a complement to the old schema previously accepted by
OpenLDAP. (BZ#1184938)

* With this update, the user can selectively disable the Generic
Security Services API (GSSAPI) key exchange algorithms as any normal
key exchange. (BZ#1253062)

Users of openssh are advised to upgrade to these updated packages,
which correct these issues and add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-November/002521.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b895ea2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-keycat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-server-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssh-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssh-askpass-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssh-clients-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssh-keycat-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssh-ldap-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssh-server-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssh-server-sysvinit-6.6.1p1-22.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pam_ssh_agent_auth-0.9.3-9.22.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
