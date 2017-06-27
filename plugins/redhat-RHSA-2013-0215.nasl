#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0215. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64389);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2012-5659", "CVE-2012-5660");
  script_bugtraq_id(57661, 57662);
  script_osvdb_id(91261, 91265);
  script_xref(name:"RHSA", value:"2013:0215");

  script_name(english:"RHEL 6 : abrt and libreport (RHSA-2013:0215)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated abrt and libreport packages that fix two security issues are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

ABRT (Automatic Bug Reporting Tool) is a tool to help users to detect
defects in applications and to create a bug report with all the
information needed by a maintainer to fix it. It uses a plug-in system
to extend its functionality. libreport provides an API for reporting
different problems in applications to different bug targets, such as
Bugzilla, FTP, and Trac.

It was found that the
/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache tool did not
sufficiently sanitize its environment variables. This could lead to
Python modules being loaded and run from non-standard directories
(such as /tmp/). A local attacker could use this flaw to escalate
their privileges to that of the abrt user. (CVE-2012-5659)

A race condition was found in the way ABRT handled the directories
used to store information about crashes. A local attacker with the
privileges of the abrt user could use this flaw to perform a symbolic
link attack, possibly allowing them to escalate their privileges to
root. (CVE-2012-5660)

Red Hat would like to thank Martin Carpenter of Citco for reporting
the CVE-2012-5660 issue. CVE-2012-5659 was discovered by Miloslav
Trmac of Red Hat.

All users of abrt and libreport are advised to upgrade to these
updated packages, which correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5659.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5660.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0215.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-addon-ccpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-addon-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-addon-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-addon-vmcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-mailx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-reportuploader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-rhtsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/01");
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
  rhsa = "RHSA-2013:0215";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-addon-ccpp-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-addon-ccpp-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-addon-ccpp-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-addon-kerneloops-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-addon-kerneloops-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-addon-kerneloops-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-addon-python-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-addon-python-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-addon-python-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-addon-vmcore-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-addon-vmcore-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-addon-vmcore-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-cli-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-cli-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-cli-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"abrt-debuginfo-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-desktop-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-desktop-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-desktop-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"abrt-devel-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-gui-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-gui-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-gui-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"abrt-libs-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"abrt-tui-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"abrt-tui-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"abrt-tui-2.0.8-6.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libreport-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-cli-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-cli-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-cli-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libreport-debuginfo-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libreport-devel-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libreport-gtk-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libreport-gtk-devel-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-newt-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-newt-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-newt-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-bugzilla-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-bugzilla-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-bugzilla-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-kerneloops-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-kerneloops-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-kerneloops-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-logger-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-logger-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-logger-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-mailx-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-mailx-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-mailx-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-reportuploader-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-reportuploader-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-reportuploader-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-plugin-rhtsupport-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-plugin-rhtsupport-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-plugin-rhtsupport-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libreport-python-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libreport-python-2.0.9-5.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libreport-python-2.0.9-5.el6_3.2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrt / abrt-addon-ccpp / abrt-addon-kerneloops / abrt-addon-python / etc");
  }
}
