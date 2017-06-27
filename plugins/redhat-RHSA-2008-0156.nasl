#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0156. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40716);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/03 17:16:32 $");

  script_cve_id("CVE-2007-5232", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273", "CVE-2008-0657");
  script_bugtraq_id(25918, 27650);
  script_osvdb_id(45527);
  script_xref(name:"RHSA", value:"2008:0156");

  script_name(english:"RHEL 4 / 5 : java-1.5.0-bea (RHSA-2008:0156)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.5.0-bea packages that correct several security issues
are now available for Red Hat Enterprise Linux 4 Extras and 5
Supplementary.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The BEA WebLogic JRockit 1.5.0_14 JRE and SDK contain BEA WebLogic
JRockit Virtual Machine 1.5.0_14 and are certified for the Java 5
Platform, Standard Edition, v1.5.0.

A flaw in the applet caching mechanism of the Java Runtime Environment
(JRE) did not correctly process the creation of network connections. A
remote attacker could use this flaw to create connections to services
on machines other than the one that the applet was downloaded from.
(CVE-2007-5232)

Untrusted Java Applets were able to drag and drop a file to a Desktop
Application. A user-assisted remote attacker could use this flaw to
move or copy arbitrary files. (CVE-2007-5239)

The Java Runtime Environment (JRE) allowed untrusted Java Applets or
applications to display oversized windows. This could be used by
remote attackers to hide security warning banners. (CVE-2007-5240)

Unsigned Java Applets communicating via a HTTP proxy could allow a
remote attacker to violate the Java security model. A cached,
malicious Applet could create network connections to services on other
machines. (CVE-2007-5273)

Two vulnerabilities in the Java Runtime Environment allowed an
untrusted application or applet to elevate the assigned privileges.
This could be misused by a malicious website to read and write local
files or execute local applications in the context of the user running
the Java process. (CVE-2008-0657)

Those vulnerabilities concerned with applets can only be triggered in
java-1.5.0-bea by calling the 'appletviewer' application.

All users of java-1.5.0-bea should upgrade to these updated packages,
which contain the BEA WebLogic JRockit 1.5.0_14 release that resolves
these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5232.html"
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
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0657.html"
  );
  # http://dev2dev.bea.com/pub/advisory/272
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7dd1a2b1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0156.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-bea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-bea-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-bea-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-bea-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-bea-missioncontrol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-bea-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/05");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0156";
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
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.5.0-bea-1.5.0.14-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-bea-1.5.0.14-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.5.0-bea-demo-1.5.0.14-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-bea-demo-1.5.0.14-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.5.0-bea-devel-1.5.0.14-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-bea-devel-1.5.0.14-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.5.0-bea-jdbc-1.5.0.14-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-bea-jdbc-1.5.0.14-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.5.0-bea-src-1.5.0.14-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-bea-src-1.5.0.14-1jpp.1.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.5.0-bea-1.5.0.14-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-bea-1.5.0.14-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.5.0-bea-demo-1.5.0.14-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-bea-demo-1.5.0.14-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.5.0-bea-devel-1.5.0.14-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-bea-devel-1.5.0.14-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.5.0-bea-jdbc-1.5.0.14-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-bea-jdbc-1.5.0.14-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.5.0-bea-missioncontrol-1.5.0.14-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-bea-missioncontrol-1.5.0.14-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.5.0-bea-src-1.5.0.14-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-bea-src-1.5.0.14-1jpp.1.el5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.5.0-bea / java-1.5.0-bea-demo / java-1.5.0-bea-devel / etc");
  }
}
