#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1919. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86524);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/01/06 16:01:53 $");

  script_cve_id("CVE-2015-4734", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806", "CVE-2015-4835", "CVE-2015-4840", "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4868", "CVE-2015-4872", "CVE-2015-4881", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4903", "CVE-2015-4911");
  script_osvdb_id(129119, 129120, 129121, 129122, 129123, 129124, 129125, 129127, 129129, 129132, 129133, 129134, 129135, 129136, 129137, 129138, 129139, 129140);
  script_xref(name:"RHSA", value:"2015:1919");

  script_name(english:"RHEL 6 / 7 : java-1.8.0-openjdk (RHSA-2015:1919)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.8.0-openjdk packages that fix multiple security issues
are now available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Multiple flaws were discovered in the CORBA, Libraries, RMI,
Serialization, and 2D components in OpenJDK. An untrusted Java
application or applet could use these flaws to completely bypass Java
sandbox restrictions. (CVE-2015-4835, CVE-2015-4881, CVE-2015-4843,
CVE-2015-4883, CVE-2015-4860, CVE-2015-4805, CVE-2015-4844)

Multiple denial of service flaws were found in the JAXP component in
OpenJDK. A specially crafted XML file could cause a Java application
using JAXP to consume an excessive amount of CPU and memory when
parsed. (CVE-2015-4803, CVE-2015-4893, CVE-2015-4911)

A flaw was found in the way the Libraries component in OpenJDK handled
certificate revocation lists (CRL). In certain cases, CRL checking
code could fail to report a revoked certificate, causing the
application to accept it as trusted. (CVE-2015-4868)

It was discovered that the Security component in OpenJDK failed to
properly check if a certificate satisfied all defined constraints. In
certain cases, this could cause a Java application to accept an X.509
certificate which does not meet requirements of the defined policy.
(CVE-2015-4872)

Multiple flaws were found in the Libraries, 2D, CORBA, JAXP, JGSS, and
RMI components in OpenJDK. An untrusted Java application or applet
could use these flaws to bypass certain Java sandbox restrictions.
(CVE-2015-4806, CVE-2015-4840, CVE-2015-4882, CVE-2015-4842,
CVE-2015-4734, CVE-2015-4903)

Red Hat would like to thank Andrea Palazzo of Truel IT for reporting
the CVE-2015-4806 issue.

All users of java-1.8.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4734.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4803.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4806.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4840.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4842.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4843.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4844.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4860.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4868.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4872.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4881.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4882.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4883.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4893.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4903.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4911.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-1919.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");
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
  rhsa = "RHSA-2015:1919";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-debug-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-debug-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-demo-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-devel-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-headless-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-src-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-src-debug-1.8.0.65-0.b17.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-debug-1.8.0.65-0.b17.el6_7")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-1.8.0.65-2.b17.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.65-2.b17.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-accessibility-1.8.0.65-2.b17.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.65-2.b17.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.65-2.b17.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.65-2.b17.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-demo-1.8.0.65-2.b17.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.65-2.b17.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-devel-1.8.0.65-2.b17.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.65-2.b17.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-headless-1.8.0.65-2.b17.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.65-2.b17.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"java-1.8.0-openjdk-javadoc-1.8.0.65-2.b17.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-src-1.8.0.65-2.b17.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.65-2.b17.el7_1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / etc");
  }
}
