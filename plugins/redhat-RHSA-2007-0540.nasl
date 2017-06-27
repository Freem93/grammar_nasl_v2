#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0540. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27829);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/29 15:45:03 $");

  script_cve_id("CVE-2006-5052", "CVE-2007-3102");
  script_bugtraq_id(20245);
  script_osvdb_id(39214);
  script_xref(name:"RHSA", value:"2007:0540");

  script_name(english:"RHEL 5 : openssh (RHSA-2007:0540)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix a security issue and various bugs
are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation. These
packages include the core files necessary for both the OpenSSH client
and server.

A flaw was found in the way the ssh server wrote account names to the
audit subsystem. An attacker could inject strings containing parts of
audit messages, which could possibly mislead or confuse audit log
parsing tools. (CVE-2007-3102)

A flaw was found in the way the OpenSSH server processes GSSAPI
authentication requests. When GSSAPI authentication was enabled in the
OpenSSH server, a remote attacker was potentially able to determine if
a username is valid. (CVE-2006-5052)

The following bugs in SELinux MLS (Multi-Level Security) support has
also been fixed in this update :

* It was sometimes not possible to select a SELinux role and level
when logging in using ssh.

* If the user obtained a non-default SELinux role or level, the role
change was not recorded in the audit subsystem.

* In some cases, on labeled networks, sshd allowed logins from level
ranges it should not allow.

The updated packages also contain experimental support for using
private keys stored in PKCS#11 tokens for client authentication. The
support is provided through the NSS (Network Security Services)
library.

All users of openssh should upgrade to these updated packages, which
contain patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-5052.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3102.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0540.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0540";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssh-4.3p2-24.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssh-4.3p2-24.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssh-4.3p2-24.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssh-askpass-4.3p2-24.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssh-askpass-4.3p2-24.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssh-askpass-4.3p2-24.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssh-clients-4.3p2-24.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssh-clients-4.3p2-24.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssh-clients-4.3p2-24.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssh-server-4.3p2-24.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssh-server-4.3p2-24.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssh-server-4.3p2-24.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-clients / openssh-server");
  }
}
