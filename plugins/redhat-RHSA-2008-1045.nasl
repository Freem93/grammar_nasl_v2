#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:1045. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40735);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/01/03 17:16:34 $");

  script_cve_id("CVE-2008-3103", "CVE-2008-3104", "CVE-2008-3105", "CVE-2008-3106", "CVE-2008-3109", "CVE-2008-3110");
  script_bugtraq_id(30140, 30143, 30146, 30147);
  script_osvdb_id(46964);
  script_xref(name:"RHSA", value:"2008:1045");

  script_name(english:"RHEL 4 / 5 : java-1.6.0-bea (RHSA-2008:1045)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1.6.0-bea as shipped in Red Hat Enterprise Linux 4 Extras and Red
Hat Enterprise Linux 5 Supplementary, contains security flaws and
should not be used.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The BEA WebLogic JRockit JRE and SDK contains BEA WebLogic JRockit
Virtual Machine and is certified for the Java(tm) 2 Platform, Standard
Edition, v1.6.0.

The java-1.6.0-bea packages are vulnerable to important security flaws
and should no longer be used.

A flaw was found in the Java Management Extensions (JMX) management
agent. When local monitoring was enabled, remote attackers could use
this flaw to perform illegal operations. (CVE-2008-3103)

Several flaws involving the handling of unsigned applets were found. A
remote attacker could misuse an unsigned applet in order to connect to
services on the host running the applet. (CVE-2008-3104)

Several flaws in the Java API for XML Web Services (JAX-WS) client and
the JAX-WS service implementation were found. A remote attacker who
could cause malicious XML to be processed by an application could
access URLs, or cause a denial of service. (CVE-2008-3105,
CVE-2008-3106)

Several flaws within the Java Runtime Environment's (JRE) scripting
support were found. A remote attacker could grant an untrusted applet
extended privileges, such as reading and writing local files,
executing local programs, or querying the sensitive data of other
applets. (CVE-2008-3109, CVE-2008-3110)

The vulnerabilities concerning applets listed above can only be
triggered in java-1.6.0-bea, by calling the 'appletviewer'
application.

BEA was acquired by Oracle(r) during 2008 (the acquisition was
completed on April 29, 2008). Consequently, JRockit is now an Oracle
offering and these issues are addressed in the current release of
Oracle JRockit. Due to a license change by Oracle, however, Red Hat is
unable to ship Oracle JRockit.

Users who wish to continue using JRockit should get an update directly
from Oracle: http://oracle.com/technology/software/products/jrockit/.

Alternatives to Oracle JRockit include the Java 2 Technology Edition
of the IBM(r) Developer Kit for Linux and the Sun(tm) Java SE
Development Kit (JDK), both of which are available on the Extras or
Supplementary channels. For Java 6 users, the new OpenJDK open source
JDK will be included in Red Hat Enterprise Linux 5.3 and will be
supported by Red Hat.

This update removes the java-1.6.0-bea packages due to their known
security vulnerabilities."
  );
  # https://support.bea.com/application_content/product_portlets/securityadvisories
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?826d01e9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-1045.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-bea-uninstall package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-bea-uninstall");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/18");
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
  rhsa = "RHSA-2008:1045";
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
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.6.0-bea-uninstall-1.6.0.03-1jpp.4.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.6.0-bea-uninstall-1.6.0.03-1jpp.4.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.6.0-bea-uninstall-1.6.0.03-1jpp.6.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-bea-uninstall-1.6.0.03-1jpp.6.el5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-bea-uninstall");
  }
}
