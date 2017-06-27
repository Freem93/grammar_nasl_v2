#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1591. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71007);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2010-5107");
  script_bugtraq_id(58162);
  script_osvdb_id(90007);
  script_xref(name:"RHSA", value:"2013:1591");

  script_name(english:"RHEL 6 : openssh (RHSA-2013:1591)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages that fix one security issue, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

OpenSSH is OpenBSD's Secure Shell (SSH) protocol implementation. These
packages include the core files necessary for the OpenSSH client and
server.

The default OpenSSH configuration made it easy for remote attackers to
exhaust unauthorized connection slots and prevent other users from
being able to log in to a system. This flaw has been addressed by
enabling random early connection drops by setting MaxStartups to
10:30:100 by default. For more information, refer to the
sshd_config(5) man page. (CVE-2010-5107)

These updated openssh packages include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.5
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All openssh users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-5107.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64c6b598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1591.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b506c4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1591";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssh-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssh-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssh-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssh-askpass-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssh-askpass-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssh-askpass-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssh-clients-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssh-clients-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssh-clients-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"openssh-debuginfo-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssh-ldap-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssh-ldap-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssh-ldap-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssh-server-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssh-server-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssh-server-5.3p1-94.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pam_ssh_agent_auth-0.9.3-94.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-clients / openssh-debuginfo / etc");
  }
}
