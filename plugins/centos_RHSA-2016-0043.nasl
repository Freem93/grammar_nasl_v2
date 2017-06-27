#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0043 and 
# CentOS Errata and Security Advisory 2016:0043 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87930);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2016-0777", "CVE-2016-0778");
  script_osvdb_id(132883, 132884);
  script_xref(name:"RHSA", value:"2016:0043");

  script_name(english:"CentOS 7 : openssh (CESA-2016:0043)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix two security issues are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSH is OpenBSD's SSH (Secure Shell) protocol implementation. These
packages include the core files necessary for both the OpenSSH client
and server.

An information leak flaw was found in the way the OpenSSH client
roaming feature was implemented. A malicious server could potentially
use this flaw to leak portions of memory (possibly including private
SSH keys) of a successfully authenticated OpenSSH client.
(CVE-2016-0777)

A buffer overflow flaw was found in the way the OpenSSH client roaming
feature was implemented. A malicious server could potentially use this
flaw to execute arbitrary code on a successfully authenticated OpenSSH
client if that client used certain non-default configuration options.
(CVE-2016-0778)

Red Hat would like to thank Qualys for reporting these issues.

All openssh users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the OpenSSH server daemon (sshd) will be
restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-January/021614.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d71bf43"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssh-6.6.1p1-23.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssh-askpass-6.6.1p1-23.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssh-clients-6.6.1p1-23.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssh-keycat-6.6.1p1-23.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssh-ldap-6.6.1p1-23.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssh-server-6.6.1p1-23.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssh-server-sysvinit-6.6.1p1-23.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pam_ssh_agent_auth-0.9.3-9.23.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
