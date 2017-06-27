#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0963. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40709);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/29 15:45:04 $");

  script_cve_id("CVE-2007-5232", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273", "CVE-2007-5274", "CVE-2007-5689");
  script_bugtraq_id(25918, 25920);
  script_osvdb_id(37759, 37760, 37761, 37762, 37763, 37764, 37765, 45527);
  script_xref(name:"RHSA", value:"2007:0963");

  script_name(english:"RHEL 4 / 5 : java-1.5.0-sun (RHSA-2007:0963)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.5.0-sun packages that correct several security issues
are now available for Red Hat Enterprise Linux 4 Extras and 5
Supplementary.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Java Runtime Environment (JRE) contains the software and tools
that users need to run applets and applications written using the Java
programming language.

A flaw in the applet caching mechanism of the Java Runtime Environment
(JRE) did not correctly process the creation of network connections. A
remote attacker could use this flaw to create connections to services
on machines other than the one that the applet was downloaded from.
(CVE-2007-5232)

Multiple vulnerabilities existed in Java Web Start allowing an
untrusted application to determine the location of the Java Web Start
cache. (CVE-2007-5238)

Untrusted Java Web Start Applications or Java Applets were able to
drag and drop a file to a Desktop Application. A user-assisted remote
attacker could use this flaw to move or copy arbitrary files.
(CVE-2007-5239)

The Java Runtime Environment (JRE) allowed untrusted Java Applets or
applications to display oversized Windows. This could be used by
remote attackers to hide security warning banners. (CVE-2007-5240)

Unsigned Java Applets communicating via a HTTP proxy could allow a
remote attacker to violate the Java security model. A cached,
malicious Applet could create network connections to services on other
machines. (CVE-2007-5273)

Unsigned Applets loaded with Mozilla Firefox or Opera browsers allowed
remote attackers to violate the Java security model. A cached,
malicious Applet could create network connections to services on other
machines. (CVE-2007-5274)

In Red Hat Enterprise Linux a Java Web Start application requesting
elevated permissions is only started automatically when signed with a
trusted code signing certificate and otherwise requires user
confirmation to access privileged resources.

All users of java-sun-1.5.0 should upgrade to these packages, which
contain Sun Java 1.5.0 Update 13 that corrects these issues.

Please note that during our quality testing we discovered that the
Java browser plug-in may not function perfectly when visiting some
sites that make use of multiple applets on a single HTML page. We have
verified that this issue is not due to our packaging and affects Sun
Java 1.5.0 Update 13."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5232.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5238.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5239.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5240.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5273.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5274.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5689.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0963.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2007:0963";
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
  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-1.5.0.13-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-1.5.0.13-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-demo-1.5.0.13-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-demo-1.5.0.13-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-devel-1.5.0.13-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-devel-1.5.0.13-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-jdbc-1.5.0.13-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-jdbc-1.5.0.13-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-plugin-1.5.0.13-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-src-1.5.0.13-1jpp.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-src-1.5.0.13-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-1.5.0.13-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-1.5.0.13-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-demo-1.5.0.13-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-demo-1.5.0.13-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-devel-1.5.0.13-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-devel-1.5.0.13-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-jdbc-1.5.0.13-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-jdbc-1.5.0.13-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-plugin-1.5.0.13-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-src-1.5.0.13-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-src-1.5.0.13-1jpp.1.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.5.0-sun / java-1.5.0-sun-demo / java-1.5.0-sun-devel / etc");
  }
}
