#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1287 and 
# CentOS Errata and Security Advisory 2009:1287 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43781);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2008-5161");
  script_bugtraq_id(32319);
  script_osvdb_id(50036);
  script_xref(name:"RHSA", value:"2009:1287");

  script_name(english:"CentOS 5 : openssh (CESA-2009:1287)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix a security issue, a bug, and add
enhancements are now available for Red Hat Enterprise Linux 5.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure Shell) protocol implementation. These
packages include the core files necessary for both the OpenSSH client
and server.

A flaw was found in the SSH protocol. An attacker able to perform a
man-in-the-middle attack may be able to obtain a portion of plain text
from an arbitrary ciphertext block when a CBC mode cipher was used to
encrypt SSH communication. This update helps mitigate this attack:
OpenSSH clients and servers now prefer CTR mode ciphers to CBC mode,
and the OpenSSH server now reads SSH packets up to their full possible
length when corruption is detected, rather than reporting errors
early, reducing the possibility of successful plain text recovery.
(CVE-2008-5161)

This update also fixes the following bug :

* the ssh client hung when trying to close a session in which a
background process still held tty file descriptors open. With this
update, this so-called 'hang on exit' error no longer occurs and the
ssh client closes the session immediately. (BZ#454812)

In addition, this update adds the following enhancements :

* the SFTP server can now chroot users to various directories,
including a user's home directory, after log in. A new configuration
option -- ChrootDirectory -- has been added to '/etc/ssh/sshd_config'
for setting this up (the default is not to chroot users). Details
regarding configuring this new option are in the sshd_config(5) manual
page. (BZ#440240)

* the executables which are part of the OpenSSH FIPS module which is
being validated will check their integrity and report their FIPS mode
status to the system log or to the terminal. (BZ#467268, BZ#492363)

All OpenSSH users are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues and add these
enhancements. After installing this update, the OpenSSH server daemon
(sshd) will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016141.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?901f131e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016142.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0aab858"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"openssh-4.3p2-36.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssh-askpass-4.3p2-36.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssh-clients-4.3p2-36.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssh-server-4.3p2-36.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
