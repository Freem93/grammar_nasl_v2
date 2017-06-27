#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1485. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84955);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2017/01/06 16:01:52 $");

  script_cve_id("CVE-2015-1931", "CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2619", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2632", "CVE-2015-2637", "CVE-2015-2638", "CVE-2015-2664", "CVE-2015-4000", "CVE-2015-4729", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4736", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760");
  script_osvdb_id(122331, 124489, 124617, 124619, 124621, 124622, 124623, 124624, 124625, 124627, 124628, 124629, 124630, 124631, 124633, 124634, 124636, 124637, 124639, 124946);
  script_xref(name:"RHSA", value:"2015:1485");

  script_name(english:"RHEL 6 / 7 : java-1.7.1-ibm (RHSA-2015:1485) (Logjam)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.7.1-ibm packages that fix several security issues are
now available for Red Hat Enterprise Linux 6 and 7 Supplementary.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

IBM Java SE version 7 Release 1 includes the IBM Java Runtime
Environment and the IBM Java Software Development Kit.

This update fixes several vulnerabilities in the IBM Java Runtime
Environment and the IBM Java Software Development Kit. Further
information about these flaws can be found on the IBM Java Security
alerts page, listed in the References section. (CVE-2015-1931,
CVE-2015-2590, CVE-2015-2601, CVE-2015-2613, CVE-2015-2619,
CVE-2015-2621, CVE-2015-2625, CVE-2015-2632, CVE-2015-2637,
CVE-2015-2638, CVE-2015-2664, CVE-2015-4000, CVE-2015-4729,
CVE-2015-4731, CVE-2015-4732, CVE-2015-4733, CVE-2015-4736,
CVE-2015-4748, CVE-2015-4749, CVE-2015-4760)

Note: This update forces the TLS/SSL client implementation in IBM JDK
to reject DH key sizes below 768 bits to address the CVE-2015-4000
issue. Refer to Red Hat Bugzilla bug 1223211, linked to in the
References section, for additional details about this change.

All users of java-1.7.1-ibm are advised to upgrade to these updated
packages, containing the IBM Java SE 7R1 SR3-FP10 release. All running
instances of IBM Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-1931.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2590.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2601.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2613.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2619.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2621.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2625.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2632.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2637.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2638.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2664.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4729.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4731.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4732.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4733.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4736.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4748.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4749.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4760.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ibm.com/developerworks/java/jdk/alerts/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1223211#c33"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-1485.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2015:1485";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.1-ibm-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.7.1-ibm-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.1-ibm-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.1-ibm-demo-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.7.1-ibm-demo-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.1-ibm-demo-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.1-ibm-devel-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.7.1-ibm-devel-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.1-ibm-devel-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.1-ibm-jdbc-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.7.1-ibm-jdbc-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.1-ibm-jdbc-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.1-ibm-plugin-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.1-ibm-plugin-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.1-ibm-src-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.7.1-ibm-src-1.7.1.3.10-1jpp.3.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.1-ibm-src-1.7.1.3.10-1jpp.3.el6_7")) flag++;


  if (rpm_check(release:"RHEL7", reference:"java-1.7.1-ibm-1.7.1.3.10-1jpp.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.1-ibm-demo-1.7.1.3.10-1jpp.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-demo-1.7.1.3.10-1jpp.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"java-1.7.1-ibm-devel-1.7.1.3.10-1jpp.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.1-ibm-jdbc-1.7.1.3.10-1jpp.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-jdbc-1.7.1.3.10-1jpp.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-plugin-1.7.1.3.10-1jpp.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.1-ibm-src-1.7.1.3.10-1jpp.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-src-1.7.1.3.10-1jpp.1.el7_1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.1-ibm / java-1.7.1-ibm-demo / java-1.7.1-ibm-devel / etc");
  }
}
