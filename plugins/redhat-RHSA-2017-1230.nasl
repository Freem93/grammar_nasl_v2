#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1230. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100172);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/15 14:02:24 $");

  script_cve_id("CVE-2017-8291");
  script_osvdb_id(156431);
  script_xref(name:"RHSA", value:"2017:1230");

  script_name(english:"RHEL 6 / 7 : ghostscript (RHSA-2017:1230)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ghostscript is now available for Red Hat Enterprise
Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Ghostscript suite contains utilities for rendering PostScript and
PDF documents. Ghostscript translates PostScript code to common bitmap
formats so that the code can be displayed or printed.

Security Fix(es) :

* It was found that ghostscript did not properly validate the
parameters passed to the .rsdparams and .eqproc functions. During its
execution, a specially crafted PostScript document could execute code
in the context of the ghostscript process, bypassing the -dSAFER
protection. (CVE-2017-8291)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-8291.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-1230.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/15");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1230";
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
  if (rpm_check(release:"RHEL6", reference:"ghostscript-8.70-23.el6_9.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"ghostscript-debuginfo-8.70-23.el6_9.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"ghostscript-devel-8.70-23.el6_9.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ghostscript-doc-8.70-23.el6_9.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ghostscript-doc-8.70-23.el6_9.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ghostscript-doc-8.70-23.el6_9.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ghostscript-gtk-8.70-23.el6_9.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ghostscript-gtk-8.70-23.el6_9.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ghostscript-gtk-8.70-23.el6_9.2")) flag++;


  if (rpm_check(release:"RHEL7", reference:"ghostscript-9.07-20.el7_3.5")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"ghostscript-9.07-20.el7_3.5")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"ghostscript-9.07-20.el7_3.5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ghostscript-cups-9.07-20.el7_3.5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ghostscript-cups-9.07-20.el7_3.5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"ghostscript-debuginfo-9.07-20.el7_3.5")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"ghostscript-debuginfo-9.07-20.el7_3.5")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"ghostscript-debuginfo-9.07-20.el7_3.5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"ghostscript-devel-9.07-20.el7_3.5")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"ghostscript-devel-9.07-20.el7_3.5")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"ghostscript-devel-9.07-20.el7_3.5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"ghostscript-doc-9.07-20.el7_3.5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ghostscript-gtk-9.07-20.el7_3.5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ghostscript-gtk-9.07-20.el7_3.5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-cups / ghostscript-debuginfo / etc");
  }
}
