#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-191.
#

include("compat.inc");

if (description)
{
  script_id(69749);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2013-2071");
  script_xref(name:"ALAS", value:"2013-191");

  script_name(english:"Amazon Linux AMI : tomcat7 (ALAS-2013-191)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java/org/apache/catalina/core/AsyncContextImpl.java in Apache Tomcat
7.x before 7.0.40 does not properly handle the throwing of a
RuntimeException in an AsyncListener in an application, which allows
context-dependent attackers to obtain sensitive request information
intended for other applications in opportunistic circumstances via an
application that records the requests that it processes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-191.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update tomcat7' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tomcat7-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"tomcat7-7.0.40-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-admin-webapps-7.0.40-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-docs-webapp-7.0.40-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-el-2.2-api-7.0.40-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-javadoc-7.0.40-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-jsp-2.2-api-7.0.40-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-lib-7.0.40-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-servlet-3.0-api-7.0.40-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat7-webapps-7.0.40-1.26.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat7 / tomcat7-admin-webapps / tomcat7-docs-webapp / etc");
}
