#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0956. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40708);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/29 15:45:04 $");

  script_cve_id("CVE-2007-0243", "CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3503", "CVE-2007-3698", "CVE-2007-4381");
  script_bugtraq_id(22085, 24004, 24846, 25340);
  script_osvdb_id(32834, 36199, 36200, 36201, 36202, 36488, 36663, 37766);
  script_xref(name:"RHSA", value:"2007:0956");

  script_name(english:"RHEL 4 / 5 : java-1.5.0-bea (RHSA-2007:0956)");
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

The BEA WebLogic JRockit 1.5.0_11 JRE and SDK contain BEA WebLogic
JRockit Virtual Machine 1.5.0_11 and are certified for the Java 5
Platform, Standard Edition, v1.5.0.

A flaw was found in the BEA Java Runtime Environment GIF image
handling. If an application processes untrusted GIF image input, it
may be possible to execute arbitrary code as the user running the Java
Virtual Machine. (CVE-2007-0243)

A buffer overflow in the Java Runtime Environment image handling code
was found. If an attacker is able to cause a server application to
process a specially crafted image file, it may be possible to execute
arbitrary code as the user running the Java Virtual Machine.
(CVE-2007-2788, CVE-2007-2789, CVE-2007-3004)

A denial of service flaw was discovered in the Java Applet Viewer. An
untrusted Java applet could cause the Java Virtual Machine to become
unresponsive. Please note that the BEA WebLogic JRockit 1.5.0_11 does
not ship with a browser plug-in and therefore this issue could only be
triggered by a user running the 'appletviewer' application.
(CVE-2007-3005)

A cross site scripting (XSS) flaw was found in the Javadoc tool. An
attacker could inject arbitrary content into a Javadoc generated HTML
documentation page, possibly tricking a user or stealing sensitive
information. (CVE-2007-3503)

A denial of service flaw was found in the way the JSSE component
processed SSL/TLS handshake requests. A remote attacker able to
connect to a JSSE enabled service could send a specially crafted
handshake which would cause the Java Runtime Environment to stop
responding to future requests. (CVE-2007-3698)

A flaw was found in the way the Java Runtime Environment processes
font data. An applet viewed via the 'appletviewer' application could
elevate its privileges, allowing the applet to perform actions with
the same permissions as the user running the 'appletviewer'
application. It may also be possible to crash a server application
which processes untrusted font information from a third party.
(CVE-2007-4381)

All users of java-bea-1.5.0 should upgrade to these updated packages,
which contain the BEA WebLogic JRockit 1.5.0_11 release that resolves
these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0243.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2788.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2789.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3503.html"
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
    value:"http://rhn.redhat.com/errata/RHSA-2007-0956.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-bea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-bea-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-bea-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-bea-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-bea-missioncontrol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-bea-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/16");
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
  rhsa = "RHSA-2007:0956";
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
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.5.0-bea-1.5.0.11-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-bea-1.5.0.11-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.5.0-bea-demo-1.5.0.11-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-bea-demo-1.5.0.11-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.5.0-bea-devel-1.5.0.11-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-bea-devel-1.5.0.11-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.5.0-bea-jdbc-1.5.0.11-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-bea-jdbc-1.5.0.11-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.5.0-bea-src-1.5.0.11-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-bea-src-1.5.0.11-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.5.0-bea-1.5.0.11-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-bea-1.5.0.11-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.5.0-bea-demo-1.5.0.11-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-bea-demo-1.5.0.11-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.5.0-bea-devel-1.5.0.11-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-bea-devel-1.5.0.11-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.5.0-bea-jdbc-1.5.0.11-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-bea-jdbc-1.5.0.11-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.5.0-bea-missioncontrol-1.5.0.11-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-bea-missioncontrol-1.5.0.11-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.5.0-bea-src-1.5.0.11-1jpp.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-bea-src-1.5.0.11-1jpp.1.el5")) flag++;

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
