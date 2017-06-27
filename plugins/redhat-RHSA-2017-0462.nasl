#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0462. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97630);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/13 15:28:56 $");

  script_cve_id("CVE-2016-2183");
  script_osvdb_id(143387, 143388);
  script_xref(name:"RHSA", value:"2017:0462");

  script_name(english:"RHEL 6 / 7 : java-1.8.0-ibm (RHSA-2017:0462)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for java-1.8.0-ibm is now available for Red Hat Enterprise
Linux 6 Supplementary and Red Hat Enterprise Linux 7 Supplementary.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

IBM Java SE version 8 includes the IBM Java Runtime Environment and
the IBM Java Software Development Kit.

This update upgrades IBM Java SE 8 to version 8 SR4-FP1.

Security Fix(es) :

* This update fixes a vulnerability in the IBM Java Runtime
Environment and the IBM Java Software Development Kit. Further
information about this flaw can be found on the IBM Java Security
alerts page, listed in the References section. (CVE-2016-2183)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2183.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://developer.ibm.com/javasdk/support/security-vulnerabilities/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0462.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:X/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/09");
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
  rhsa = "RHSA-2017:0462";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-ibm-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.8.0-ibm-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-ibm-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-ibm-demo-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.8.0-ibm-demo-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-ibm-demo-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-ibm-devel-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.8.0-ibm-devel-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-ibm-devel-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-ibm-jdbc-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.8.0-ibm-jdbc-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-ibm-jdbc-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-ibm-plugin-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-ibm-plugin-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-ibm-src-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.8.0-ibm-src-1.8.0.4.1-1jpp.1.el6_8")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-ibm-src-1.8.0.4.1-1jpp.1.el6_8")) flag++;

  if (rpm_check(release:"RHEL7", reference:"java-1.8.0-ibm-1.8.0.4.1-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-ibm-demo-1.8.0.4.1-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-ibm-demo-1.8.0.4.1-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"java-1.8.0-ibm-devel-1.8.0.4.1-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-ibm-jdbc-1.8.0.4.1-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-ibm-jdbc-1.8.0.4.1-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-ibm-plugin-1.8.0.4.1-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-ibm-src-1.8.0.4.1-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-ibm-src-1.8.0.4.1-1jpp.2.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-ibm / java-1.8.0-ibm-demo / java-1.8.0-ibm-devel / etc");
  }
}
