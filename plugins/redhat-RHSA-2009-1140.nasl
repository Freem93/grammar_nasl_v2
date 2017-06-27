#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1140. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39599);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2007-1558", "CVE-2009-0642", "CVE-2009-1904");
  script_bugtraq_id(23257, 35278);
  script_osvdb_id(34856);
  script_xref(name:"RHSA", value:"2009:1140");

  script_name(english:"RHEL 4 / 5 : ruby (RHSA-2009:1140)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to do system
management tasks.

A flaw was found in the way the Ruby POP module processed certain APOP
authentication requests. By sending certain responses when the Ruby
APOP module attempted to authenticate using APOP against a POP server,
a remote attacker could, potentially, acquire certain portions of a
user's authentication credentials. (CVE-2007-1558)

It was discovered that Ruby did not properly check the return value
when verifying X.509 certificates. This could, potentially, allow a
remote attacker to present an invalid X.509 certificate, and have Ruby
treat it as valid. (CVE-2009-0642)

A flaw was found in the way Ruby converted BigDecimal objects to Float
numbers. If an attacker were able to provide certain input for the
BigDecimal object converter, they could crash an application using
this class. (CVE-2009-1904)

All Ruby users should upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-1558.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0642.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1904.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1140.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 287);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/02");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:1140";
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
  if (rpm_check(release:"RHEL4", reference:"irb-1.8.1-7.el4_8.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ruby-1.8.1-7.el4_8.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ruby-devel-1.8.1-7.el4_8.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ruby-docs-1.8.1-7.el4_8.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ruby-libs-1.8.1-7.el4_8.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ruby-mode-1.8.1-7.el4_8.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ruby-tcltk-1.8.1-7.el4_8.3")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", reference:"ruby-devel-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-docs-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-docs-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-docs-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-irb-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-irb-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-irb-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", reference:"ruby-libs-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-mode-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-mode-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-mode-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-rdoc-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-rdoc-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-rdoc-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-ri-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-ri-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-ri-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ruby-tcltk-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ruby-tcltk-1.8.5-5.el5_3.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ruby-tcltk-1.8.5-5.el5_3.7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irb / ruby / ruby-devel / ruby-docs / ruby-irb / ruby-libs / etc");
  }
}
