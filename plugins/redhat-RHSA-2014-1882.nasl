#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1882. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79379);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/06 15:51:00 $");

  script_cve_id("CVE-2014-3065", "CVE-2014-3566", "CVE-2014-4288", "CVE-2014-6456", "CVE-2014-6457", "CVE-2014-6458", "CVE-2014-6476", "CVE-2014-6492", "CVE-2014-6493", "CVE-2014-6502", "CVE-2014-6503", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6515", "CVE-2014-6527", "CVE-2014-6531", "CVE-2014-6532", "CVE-2014-6558");
  script_bugtraq_id(70456, 70460, 70468, 70470, 70507, 70518, 70522, 70531, 70533, 70538, 70544, 70548, 70556, 70560, 70565, 70567, 70572, 70574, 71147);
  script_osvdb_id(99712, 113251, 113315, 113316, 113319, 113320, 113321, 113323, 113325, 113326, 113327, 113328, 113332, 113333, 113335, 113336, 113337, 113339, 114541);
  script_xref(name:"RHSA", value:"2014:1882");

  script_name(english:"RHEL 6 : java-1.7.0-ibm (RHSA-2014:1882) (POODLE)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.7.0-ibm packages that fix several security issues are
now available for Red Hat Enterprise Linux 6 Supplementary.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

[Updated 2 December 2014] This advisory has been updated to include
updated java-1.7.0-ibm-jdbc and java-1.7.0-ibm-plugin packages, which
were previously missing from this erratum. No changes were made to the
other packages in this erratum.

IBM Java SE version 7 includes the IBM Java Runtime Environment and
the IBM Java Software Development Kit.

This update fixes several vulnerabilities in the IBM Java Runtime
Environment and the IBM Java Software Development Kit. Detailed
vulnerability descriptions are linked from the IBM Security alerts
page, listed in the References section. (CVE-2014-3065, CVE-2014-3566,
CVE-2014-4288, CVE-2014-6456, CVE-2014-6457, CVE-2014-6458,
CVE-2014-6476, CVE-2014-6492, CVE-2014-6493, CVE-2014-6502,
CVE-2014-6503, CVE-2014-6506, CVE-2014-6511, CVE-2014-6512,
CVE-2014-6515, CVE-2014-6527, CVE-2014-6531, CVE-2014-6532,
CVE-2014-6558)

The CVE-2014-6512 issue was discovered by Florian Weimer of Red Hat
Product Security.

Note: With this update, the IBM SDK now disables the SSL 3.0 protocol
to address the CVE-2014-3566 issue (also known as POODLE). Refer to
the IBM article linked to in the References section for additional
details about this change and instructions on how to re-enable SSL 3.0
support if needed.

Note: This is the last update for the java-1.7.0-ibm packages
distributed via the Red Hat Enterprise Linux 6 Supplementary channels.
The RHEA-2014:1619 advisory, released as a part of Red Hat Enterprise
Linux 6.6, introduced the new java-1.7.1-ibm packages. These packages
contain IBM Java SE version 7 Release 1, which adds multiple
enhancements over the IBM Java SE version 7 in the java-1.7.0-ibm
packages. All java-1.7.0-ibm users must migrate to java-1.7.1-ibm
packages to continue receiving updates for the IBM Java SE version 7
via the Red Hat Enterprise Linux 6 Supplementary channel.

All users of java-1.7.0-ibm are advised to upgrade to these updated
packages, containing the IBM Java SE 7 SR8 release. All running
instances of IBM Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3566.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4288.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6456.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6457.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6458.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6476.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6492.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6493.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6502.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6503.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6506.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6512.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6515.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6527.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6531.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6532.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6558.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ibm.com/developerworks/java/jdk/alerts/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www-01.ibm.com/support/docview.wss?uid=swg21688165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHEA-2014-1619.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1882.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/21");
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
  rhsa = "RHSA-2014:1882";
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
  if (rpm_check(release:"RHEL6", sp:"6", reference:"java-1.7.0-ibm-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-ibm-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.7.0-ibm-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-ibm-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-ibm-demo-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.7.0-ibm-demo-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-ibm-demo-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", sp:"6", reference:"java-1.7.0-ibm-devel-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-ibm-devel-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.7.0-ibm-devel-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-ibm-devel-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-ibm-jdbc-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.7.0-ibm-jdbc-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-ibm-jdbc-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-ibm-plugin-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-ibm-plugin-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-ibm-src-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.7.0-ibm-src-1.7.0.8.0-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-ibm-src-1.7.0.8.0-1jpp.1.el6_6")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-ibm / java-1.7.0-ibm-demo / java-1.7.0-ibm-devel / etc");
  }
}
