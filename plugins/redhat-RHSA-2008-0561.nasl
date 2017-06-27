#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0561. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33495);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2008-2376", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726");
  script_bugtraq_id(29903, 30036);
  script_osvdb_id(46553);
  script_xref(name:"RHSA", value:"2008:0561");

  script_name(english:"RHEL 4 / 5 : ruby (RHSA-2008:0561)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Ruby is an interpreted scripting language for quick and easy
object-oriented programming.

Multiple integer overflows leading to a heap overflow were discovered
in the array- and string-handling code used by Ruby. An attacker could
use these flaws to crash a Ruby application or, possibly, execute
arbitrary code with the privileges of the Ruby application using
untrusted inputs in array or string operations. (CVE-2008-2376,
CVE-2008-2662, CVE-2008-2663, CVE-2008-2725, CVE-2008-2726)

It was discovered that Ruby used the alloca() memory allocation
function in the format (%) method of the String class without properly
restricting maximum string length. An attacker could use this flaw to
crash a Ruby application or, possibly, execute arbitrary code with the
privileges of the Ruby application using long, untrusted strings as
format strings. (CVE-2008-2664)

Red Hat would like to thank Drew Yao of the Apple Product Security
team for reporting these issues.

Users of Ruby should upgrade to these updated packages, which contain
a backported patch to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2376.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2662.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2663.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2664.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2725.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2726.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0561.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0561";
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
  if (rpm_check(release:"RHEL4", reference:"irb-1.8.1-7.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ruby-1.8.1-7.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ruby-devel-1.8.1-7.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ruby-docs-1.8.1-7.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ruby-libs-1.8.1-7.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ruby-mode-1.8.1-7.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ruby-tcltk-1.8.1-7.el4_6.1")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", reference:"ruby-devel-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-docs-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-docs-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-docs-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-irb-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-irb-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-irb-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", reference:"ruby-libs-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-mode-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-mode-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-mode-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-rdoc-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-rdoc-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-rdoc-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-ri-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-ri-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-ri-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-tcltk-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-tcltk-1.8.5-5.el5_2.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-tcltk-1.8.5-5.el5_2.3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irb / ruby / ruby-devel / ruby-docs / ruby-irb / ruby-libs / etc");
  }
}
