#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-681.
#

include("compat.inc");

if (description)
{
  script_id(90274);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/11/04 15:55:09 $");

  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2016-0706", "CVE-2016-0714");
  script_xref(name:"ALAS", value:"2016-681");

  script_name(english:"Amazon Linux AMI : tomcat6 (ALAS-2016-681)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A directory traversal vulnerability in RequestUtil.java was discovered
which allows remote authenticated users to bypass intended
SecurityManager restrictions and list a parent directory via a /..
(slash dot dot) in a pathname used by a web application in a
getResource, getResourceAsStream, or getResourcePaths call.
(CVE-2015-5174)

The Mapper component processes redirects before considering security
constraints and Filters, which allows remote attackers to determine
the existence of a directory via a URL that lacks a trailing / (slash)
character. (CVE-2015-5345)

The session-persistence implementation was discovered to mishandle
session attributes, which allows remote authenticated users to bypass
intended SecurityManager restrictions and execute arbitrary code in a
privileged context via a web application that places a crafted object
in a session. (CVE-2016-0714)

It was discovered that
org.apache.catalina.manager.StatusManagerServlet was not placed on the
org/apache/catalina/core/RestrictedServlets.properties list, which
allows remote authenticated users to bypass intended SecurityManager
restrictions and read arbitrary HTTP requests, and consequently
discover session ID values, via a crafted web application.
(CVE-2016-0706)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-681.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update tomcat6' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"tomcat6-6.0.45-1.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-admin-webapps-6.0.45-1.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-docs-webapp-6.0.45-1.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-el-2.1-api-6.0.45-1.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-javadoc-6.0.45-1.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-jsp-2.1-api-6.0.45-1.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-lib-6.0.45-1.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-servlet-2.5-api-6.0.45-1.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-webapps-6.0.45-1.4.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat6 / tomcat6-admin-webapps / tomcat6-docs-webapp / etc");
}
