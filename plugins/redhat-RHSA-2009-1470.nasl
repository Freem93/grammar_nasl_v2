#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1470. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41951);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2009-2904");
  script_osvdb_id(58495);
  script_xref(name:"RHSA", value:"2009:1470");

  script_name(english:"RHEL 5 : openssh (RHSA-2009:1470)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix a security issue are now available
for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure Shell) protocol implementation. These
packages include the core files necessary for both the OpenSSH client
and server.

A Red Hat specific patch used in the openssh packages as shipped in
Red Hat Enterprise Linux 5.4 (RHSA-2009:1287) loosened certain
ownership requirements for directories used as arguments for the
ChrootDirectory configuration options. A malicious user that also has
or previously had non-chroot shell access to a system could possibly
use this flaw to escalate their privileges and run commands as any
system user. (CVE-2009-2904)

All OpenSSH users are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue. After
installing this update, the OpenSSH server daemon (sshd) will be
restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2904.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1470.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2009:1470";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssh-4.3p2-36.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssh-4.3p2-36.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssh-4.3p2-36.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssh-askpass-4.3p2-36.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssh-askpass-4.3p2-36.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssh-askpass-4.3p2-36.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssh-clients-4.3p2-36.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssh-clients-4.3p2-36.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssh-clients-4.3p2-36.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssh-server-4.3p2-36.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssh-server-4.3p2-36.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssh-server-4.3p2-36.el5_4.2")) flag++;


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
