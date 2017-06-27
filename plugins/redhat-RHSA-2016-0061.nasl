#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0061. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88077);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2017/01/10 20:34:11 $");

  script_cve_id("CVE-2013-5704", "CVE-2015-3183");
  script_osvdb_id(105190, 123122);
  script_xref(name:"RHSA", value:"2016:0061");

  script_name(english:"RHEL 5 / 6 : JBoss Web Server (RHSA-2016:0061)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd and httpd22 packages that fix two security issues are
now available for Red Hat JBoss Web Server 2.1.0 for Red Hat
Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available from the
CVE links in the References section.

Red Hat JBoss Web Server is a fully integrated and certified set of
components for hosting Java web applications. It is comprised of the
Apache HTTP Server, the Apache Tomcat Servlet container, Apache Tomcat
Connector (mod_jk), JBoss HTTP Connector (mod_cluster), Hibernate, and
the Tomcat Native library.

Multiple flaws were found in the way httpd parsed HTTP requests and
responses using chunked transfer encoding. A remote attacker could use
these flaws to create a specially crafted request, which httpd would
decode differently from an HTTP proxy software in front of it,
possibly leading to HTTP request smuggling attacks. (CVE-2015-3183)

A flaw was found in the way httpd handled HTTP Trailer headers when
processing requests using chunked encoding. A malicious client could
use Trailer headers to set additional HTTP headers after header
processing was performed by other modules. This could, for example,
lead to a bypass of header restrictions defined with mod_headers.
(CVE-2013-5704)

Users of httpd or httpd22 are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue.
After installing the updated packages, the httpd or httpd22 service
must be restarted manually for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5704.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3183.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0061.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0061";
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

  if (! (rpm_exists(release:"RHEL5", rpm:"jws-2") || rpm_exists(release:"RHEL6", rpm:"jws-2"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss Web Server");

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-2.2.26-41.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-2.2.26-41.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-devel-2.2.26-41.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-devel-2.2.26-41.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-manual-2.2.26-41.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-manual-2.2.26-41.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-tools-2.2.26-41.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-tools-2.2.26-41.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_cluster-native-1.2.9-6.Final_redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_cluster-native-1.2.9-6.Final_redhat_2.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_ssl-2.2.26-41.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_ssl-2.2.26-41.ep6.el5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-2.2.26-41.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-2.2.26-41.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-devel-2.2.26-41.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-devel-2.2.26-41.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-manual-2.2.26-41.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-manual-2.2.26-41.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-tools-2.2.26-41.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-tools-2.2.26-41.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_cluster-native-1.2.9-6.Final_redhat_2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_cluster-native-1.2.9-6.Final_redhat_2.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_ssl-2.2.26-41.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_ssl-2.2.26-41.ep6.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / httpd-tools / etc");
  }
}
