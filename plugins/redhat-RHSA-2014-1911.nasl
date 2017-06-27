#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1911. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79595);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/06 15:51:00 $");

  script_cve_id("CVE-2014-8080", "CVE-2014-8090");
  script_bugtraq_id(70935, 71230);
  script_osvdb_id(113747, 114641);
  script_xref(name:"RHSA", value:"2014:1911");

  script_name(english:"RHEL 6 : ruby (RHSA-2014:1911)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix two security issues are now available
for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to perform system
management tasks.

Multiple denial of service flaws were found in the way the Ruby REXML
XML parser performed expansion of parameter entities. A specially
crafted XML document could cause REXML to use an excessive amount of
CPU and memory. (CVE-2014-8080, CVE-2014-8090)

The CVE-2014-8090 issue was discovered by Red Hat Product Security.

All ruby users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. All running
instances of Ruby need to be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1911.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2014:1911";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ruby-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ruby-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"ruby-debuginfo-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"ruby-devel-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ruby-docs-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ruby-docs-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-docs-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ruby-irb-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ruby-irb-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-irb-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"ruby-libs-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ruby-rdoc-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ruby-rdoc-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-rdoc-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ruby-ri-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ruby-ri-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-ri-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ruby-static-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ruby-static-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-static-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ruby-tcltk-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ruby-tcltk-1.8.7.374-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-tcltk-1.8.7.374-3.el6_6")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-debuginfo / ruby-devel / ruby-docs / ruby-irb / etc");
  }
}
