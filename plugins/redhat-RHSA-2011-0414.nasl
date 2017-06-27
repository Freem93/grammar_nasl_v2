#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0414. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53293);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/04 16:02:21 $");

  script_cve_id("CVE-2011-1011");
  script_bugtraq_id(46510);
  script_osvdb_id(72541);
  script_xref(name:"RHSA", value:"2011:0414");

  script_name(english:"RHEL 6 : policycoreutils (RHSA-2011:0414)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated policycoreutils packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The policycoreutils packages contain the core utilities that are
required for the basic operation of a Security-Enhanced Linux
(SELinux) system and its policies.

It was discovered that the seunshare utility did not enforce proper
file permissions on the directory used as an alternate temporary
directory mounted as /tmp/. A local user could use this flaw to
overwrite files or, possibly, execute arbitrary code with the
privileges of a setuid or setgid application that relies on proper
/tmp/ permissions, by running that application via seunshare.
(CVE-2011-1011)

Red Hat would like to thank Tavis Ormandy for reporting this issue.

This update also introduces the following changes :

* The seunshare utility was moved from the main policycoreutils
subpackage to the policycoreutils-sandbox subpackage. This utility is
only required by the sandbox feature and does not need to be installed
by default.

* Updated selinux-policy packages that add the SELinux policy changes
required by the seunshare fixes.

All policycoreutils users should upgrade to these updated packages,
which correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0414.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:policycoreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:policycoreutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:policycoreutils-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:policycoreutils-newrole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:policycoreutils-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:policycoreutils-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:selinux-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:selinux-policy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:selinux-policy-minimum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:selinux-policy-mls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:selinux-policy-targeted");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2011:0414";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"policycoreutils-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"policycoreutils-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"policycoreutils-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"policycoreutils-debuginfo-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"policycoreutils-debuginfo-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"policycoreutils-debuginfo-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"policycoreutils-gui-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"policycoreutils-gui-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"policycoreutils-gui-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"policycoreutils-newrole-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"policycoreutils-newrole-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"policycoreutils-newrole-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"policycoreutils-python-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"policycoreutils-python-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"policycoreutils-python-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"policycoreutils-sandbox-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"policycoreutils-sandbox-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"policycoreutils-sandbox-2.0.83-19.8.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", reference:"selinux-policy-3.7.19-54.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"selinux-policy-doc-3.7.19-54.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"selinux-policy-minimum-3.7.19-54.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"selinux-policy-mls-3.7.19-54.el6_0.5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"selinux-policy-targeted-3.7.19-54.el6_0.5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "policycoreutils / policycoreutils-debuginfo / policycoreutils-gui / etc");
  }
}
