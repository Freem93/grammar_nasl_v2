#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-657.
#

include("compat.inc");

if (description)
{
  script_id(89838);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/11/04 15:55:09 $");

  script_cve_id("CVE-2014-7810", "CVE-2015-5174", "CVE-2015-5346");
  script_xref(name:"ALAS", value:"2016-657");

  script_name(english:"Amazon Linux AMI : tomcat7 (ALAS-2016-657)");
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

A session fixation vulnerability was discovered that might allow
remote attackers to hijack web sessions by leveraging use of a
requestedSessionSSL field for an unintended request when different
session settings are used for deployments of multiple versions of the
same web application. (CVE-2015-5346)

It was found that the expression language resolver evaluated
expressions within a privileged code section. A malicious web
application could use this flaw to bypass security manager
protections. (CVE-2014-7810)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-657.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update tomcat7' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/11");
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
if (rpm_check(release:"ALA", reference:"tomcat7-7.0.67-1.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-admin-webapps-7.0.67-1.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-docs-webapp-7.0.67-1.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-el-2.2-api-7.0.67-1.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-javadoc-7.0.67-1.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-jsp-2.2-api-7.0.67-1.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-lib-7.0.67-1.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-log4j-7.0.67-1.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-servlet-3.0-api-7.0.67-1.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-webapps-7.0.67-1.13.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat7 / tomcat7-admin-webapps / tomcat7-docs-webapp / etc");
}
