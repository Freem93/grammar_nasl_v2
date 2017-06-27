#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0525. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76240);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/06 15:40:57 $");

  script_cve_id("CVE-2012-3544", "CVE-2013-4286", "CVE-2013-4322", "CVE-2014-0033", "CVE-2014-0050");
  script_bugtraq_id(65400, 65767, 65769, 65773);
  script_xref(name:"RHSA", value:"2014:0525");

  script_name(english:"RHEL 5 / 6 : JBoss Web Server (RHSA-2014:0525)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tomcat6 packages that fix multiple security issues are now
available for Red Hat JBoss Web Server 2.0.1 on Red Hat Enterprise
Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat JBoss Web Server is a fully integrated and certified set of
components for hosting Java web applications. It is comprised of the
Apache HTTP Server, the Apache Tomcat Servlet container, Apache Tomcat
Connector (mod_jk), JBoss HTTP Connector (mod_cluster), Hibernate, and
the Tomcat Native library.

It was found that when Tomcat processed a series of HTTP requests in
which at least one request contained either multiple content-length
headers, or one content-length header with a chunked transfer-encoding
header, Tomcat would incorrectly handle the request. A remote attacker
could use this flaw to poison a web cache, perform cross-site
scripting (XSS) attacks, or obtain sensitive information from other
requests. (CVE-2013-4286)

It was discovered that the fix for CVE-2012-3544 did not properly
resolve a denial of service flaw in the way Tomcat processed chunk
extensions and trailing headers in chunked requests. A remote attacker
could use this flaw to send an excessively long request that, when
processed by Tomcat, could consume network bandwidth, CPU, and memory
on the Tomcat server. Note that chunked transfer encoding is enabled
by default. (CVE-2013-4322)

It was found that previous fixes in Tomcat 6 to path parameter
handling introduced a regression that caused Tomcat to not properly
disable URL rewriting to track session IDs when the
disableURLRewriting option was enabled. A man-in-the-middle attacker
could potentially use this flaw to hijack a user's session.
(CVE-2014-0033)

A denial of service flaw was found in the way Apache Commons
FileUpload, which is embedded in Tomcat, handled small-sized buffers
used by MultipartStream. A remote attacker could use this flaw to
create a malformed Content-Type header for a multipart request,
causing Tomcat to enter an infinite loop when processing such an
incoming request. (CVE-2014-0050)

All users of Red Hat JBoss Web Server 2.0.1 are advised to upgrade to
these updated tomcat6 packages, which contain backported patches to
correct these issues. The Red Hat JBoss Web Server process must be
restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4286.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4322.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0033.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0050.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0525.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0525";
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

  if (! (rpm_exists(release:"RHEL5", rpm:"jws-2") || rpm_exists(release:"RHEL6", rpm:"jws-2"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss Web Server");

  if (rpm_check(release:"RHEL5", reference:"tomcat6-6.0.37-19_patch_04.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-admin-webapps-6.0.37-19_patch_04.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-docs-webapp-6.0.37-19_patch_04.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-el-2.1-api-6.0.37-19_patch_04.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-javadoc-6.0.37-19_patch_04.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-jsp-2.1-api-6.0.37-19_patch_04.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-lib-6.0.37-19_patch_04.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-log4j-6.0.37-19_patch_04.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-servlet-2.5-api-6.0.37-19_patch_04.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat6-webapps-6.0.37-19_patch_04.ep6.el5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"tomcat6-6.0.37-27_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-admin-webapps-6.0.37-27_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-docs-webapp-6.0.37-27_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-el-2.1-api-6.0.37-27_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-javadoc-6.0.37-27_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-jsp-2.1-api-6.0.37-27_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-lib-6.0.37-27_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-log4j-6.0.37-27_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-servlet-2.5-api-6.0.37-27_patch_04.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat6-webapps-6.0.37-27_patch_04.ep6.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat6 / tomcat6-admin-webapps / tomcat6-docs-webapp / etc");
  }
}
