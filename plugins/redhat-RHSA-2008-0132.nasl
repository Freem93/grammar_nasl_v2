#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0132. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40714);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/01/03 17:16:32 $");

  script_cve_id("CVE-2007-3698", "CVE-2007-4381", "CVE-2007-5232", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273", "CVE-2007-5274", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1192", "CVE-2008-1195");
  script_bugtraq_id(24846, 25340, 25918, 25920);
  script_osvdb_id(45527);
  script_xref(name:"RHSA", value:"2008:0132");

  script_name(english:"RHEL 3 / 4 / 5 : java-1.4.2-ibm (RHSA-2008:0132)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.4.2-ibm packages that fix several security issues are
now available for Red Hat Enterprise Linux 3 and 4 Extras, and 5
Supplementary.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

IBM's 1.4.2 SR10 Java release includes the IBM Java 2 Runtime
Environment and the IBM Java 2 Software Development Kit.

The Java Secure Socket Extension (JSSE) component did not correctly
process SSL/TLS handshake requests. A remote attacker who is able to
connect to a JSSE-based service could trigger this flaw leading to a
denial-of-service. (CVE-2007-3698)

A flaw was found in the way the Java Runtime Environment processes
font data. An untrusted applet could elevate its privileges, allowing
the applet to perform actions with the same permissions as the logged
in user. It may also be possible to crash a server application which
processes untrusted font information from a third party.
(CVE-2007-4381)

The applet caching mechanism of the Java Runtime Environment (JRE) did
not correctly process the creation of network connections. A remote
attacker could use this flaw to create connections to services on
machines other than the one that the applet was downloaded from.
(CVE-2007-5232)

Multiple vulnerabilities existed in Java Web Start allowing an
untrusted application to determine the location of the Java Web Start
cache. (CVE-2007-5238)

Untrusted Java Web Start Applications or Java Applets were able to
drag and drop a file to a Desktop Application. A user-assisted remote
attacker could use this flaw to move or copy arbitrary files.
(CVE-2007-5239)

The Java Runtime Environment allowed untrusted Java Applets or
applications to display oversized Windows. This could be used by
remote attackers to hide security warning banners. (CVE-2007-5240)

Unsigned Java Applets communicating via a HTTP proxy could allow a
remote attacker to violate the Java security model. A cached malicious
Applet could create network connections to services on other machines.
(CVE-2007-5273)

Unsigned Applets loaded with Mozilla Firefox or Opera browsers allowed
remote attackers to violate the Java security model. A cached
malicious Applet could create network connections to services on other
machines. (CVE-2007-5274)

All users of java-1.4.2-ibm are advised to upgrade to these updated
packages, that contain IBM's 1.4.2 SR10 Java release which resolves
these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3698.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4381.html"
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
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1189.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1190.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1192.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1195.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0132.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm-javacomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/24");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0132";
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
  if (rpm_check(release:"RHEL3", reference:"java-1.4.2-ibm-1.4.2.10-1jpp.2.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"java-1.4.2-ibm-demo-1.4.2.10-1jpp.2.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"java-1.4.2-ibm-devel-1.4.2.10-1jpp.2.el3")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"java-1.4.2-ibm-jdbc-1.4.2.10-1jpp.2.el3")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"s390", reference:"java-1.4.2-ibm-jdbc-1.4.2.10-1jpp.2.el3")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"java-1.4.2-ibm-plugin-1.4.2.10-1jpp.2.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"java-1.4.2-ibm-src-1.4.2.10-1jpp.2.el3")) flag++;


  if (rpm_check(release:"RHEL4", reference:"java-1.4.2-ibm-1.4.2.10-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.4.2-ibm-demo-1.4.2.10-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.4.2-ibm-devel-1.4.2.10-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.4.2-ibm-javacomm-1.4.2.10-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.4.2-ibm-javacomm-1.4.2.10-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.4.2-ibm-jdbc-1.4.2.10-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"s390", reference:"java-1.4.2-ibm-jdbc-1.4.2.10-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.4.2-ibm-plugin-1.4.2.10-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.4.2-ibm-src-1.4.2.10-1jpp.2.el4")) flag++;


  if (rpm_check(release:"RHEL5", reference:"java-1.4.2-ibm-1.4.2.10-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.4.2-ibm-demo-1.4.2.10-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.4.2-ibm-devel-1.4.2.10-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.4.2-ibm-javacomm-1.4.2.10-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.4.2-ibm-javacomm-1.4.2.10-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.4.2-ibm-jdbc-1.4.2.10-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390", reference:"java-1.4.2-ibm-jdbc-1.4.2.10-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.4.2-ibm-plugin-1.4.2.10-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.4.2-ibm-src-1.4.2.10-1jpp.2.el5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.4.2-ibm / java-1.4.2-ibm-demo / java-1.4.2-ibm-devel / etc");
  }
}
