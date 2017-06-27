#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-722.
#

include("compat.inc");

if (description)
{
  script_id(92469);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/24 13:45:58 $");

  script_cve_id("CVE-2016-5388");
  script_xref(name:"ALAS", value:"2016-722");

  script_name(english:"Amazon Linux AMI : tomcat6 / tomcat7,tomcat8 (ALAS-2016-722) (httpoxy)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tomcat's CGI support used the value of the Proxy header from HTTP
requests to initialize the HTTP_PROXY environment variable for CGI
scripts, which in turn was incorrectly used by certain HTTP client
implementations to configure the proxy for outgoing HTTP requests. A
remote attacker could possibly use this flaw to redirect HTTP requests
performed by a CGI script to an attacker-controlled proxy via a
malicious HTTP request (known as the 'httpoxy' class of
vulnerabilities)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://httpoxy.org/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-722.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update tomcat6' to update your system.

Run 'yum update tomcat7' to update your system.

Run 'yum update tomcat8' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-el-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-jsp-2.3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-servlet-3.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat8-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/21");
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
if (rpm_check(release:"ALA", reference:"tomcat6-6.0.45-1.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-admin-webapps-6.0.45-1.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-docs-webapp-6.0.45-1.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-el-2.1-api-6.0.45-1.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-javadoc-6.0.45-1.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-jsp-2.1-api-6.0.45-1.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-lib-6.0.45-1.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-servlet-2.5-api-6.0.45-1.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-webapps-6.0.45-1.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-7.0.69-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-admin-webapps-7.0.69-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-docs-webapp-7.0.69-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-el-2.2-api-7.0.69-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-javadoc-7.0.69-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-jsp-2.2-api-7.0.69-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-lib-7.0.69-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-log4j-7.0.69-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-servlet-3.0-api-7.0.69-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-webapps-7.0.69-1.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-8.0.35-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-admin-webapps-8.0.35-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-docs-webapp-8.0.35-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-el-3.0-api-8.0.35-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-javadoc-8.0.35-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-jsp-2.3-api-8.0.35-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-lib-8.0.35-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-log4j-8.0.35-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-servlet-3.1-api-8.0.35-1.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-webapps-8.0.35-1.61.amzn1")) flag++;

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
