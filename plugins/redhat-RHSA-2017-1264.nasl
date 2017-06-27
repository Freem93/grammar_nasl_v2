#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1264. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100345);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/25 13:29:26 $");

  script_cve_id("CVE-2017-8422");
  script_osvdb_id(157311);
  script_xref(name:"RHSA", value:"2017:1264");

  script_name(english:"RHEL 7 : kdelibs (RHSA-2017:1264)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kdelibs is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The K Desktop Environment (KDE) is a graphical desktop environment for
the X Window System. The kdelibs packages include core libraries for
the K Desktop Environment.

Security Fix(es) :

* A privilege escalation flaw was found in the way kdelibs handled
D-Bus messages. A local user could potentially use this flaw to gain
root privileges by spoofing a callerID and leveraging a privileged
helper application. (CVE-2017-8422)

Red Hat would like to thank Sebastian Krahmer (SUSE) for reporting
this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-8422.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-1264.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-ktexteditor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1264";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL7", reference:"kdelibs-4.14.8-6.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"kdelibs-4.14.8-6.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kdelibs-4.14.8-6.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", reference:"kdelibs-apidocs-4.14.8-6.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kdelibs-common-4.14.8-6.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kdelibs-common-4.14.8-6.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", reference:"kdelibs-debuginfo-4.14.8-6.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"kdelibs-debuginfo-4.14.8-6.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kdelibs-debuginfo-4.14.8-6.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", reference:"kdelibs-devel-4.14.8-6.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"kdelibs-devel-4.14.8-6.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kdelibs-devel-4.14.8-6.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", reference:"kdelibs-ktexteditor-4.14.8-6.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"kdelibs-ktexteditor-4.14.8-6.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"kdelibs-ktexteditor-4.14.8-6.el7_3")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs / kdelibs-apidocs / kdelibs-common / kdelibs-debuginfo / etc");
  }
}
