#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-527.
#

include("compat.inc");

if (description)
{
  script_id(83497);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/05/24 04:37:33 $");

  script_cve_id("CVE-2014-0075", "CVE-2014-0096", "CVE-2014-0099", "CVE-2014-0227");
  script_xref(name:"ALAS", value:"2015-527");

  script_name(english:"Amazon Linux AMI : tomcat8 (ALAS-2015-527)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that JBoss Web / Apache Tomcat did not limit the
length of chunk sizes when using chunked transfer encoding. A remote
attacker could use this flaw to perform a denial of service attack
against JBoss Web / Apache Tomcat by streaming an unlimited quantity
of data, leading to excessive consumption of server resources.
(CVE-2014-0075)

It was found that the org.apache.catalina.servlets.DefaultServlet
implementation in JBoss Web / Apache Tomcat allowed the definition of
XML External Entities (XXEs) in provided XSLTs. A malicious
application could use this to circumvent intended security
restrictions to disclose sensitive information. (CVE-2014-0096)

It was found that JBoss Web / Apache Tomcat did not check for
overflowing values when parsing request content length headers. A
remote attacker could use this flaw to perform an HTTP request
smuggling attack on a JBoss Web / Apache Tomcat server located behind
a reverse proxy that processed the content length header correctly.
(CVE-2014-0099)

It was discovered that the ChunkedInputFilter in Tomcat did not fail
subsequent attempts to read input after malformed chunked encoding was
detected. A remote attacker could possibly use this flaw to make
Tomcat process part of the request body as new request, or cause a
denial of service. (CVE-2014-0227)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-527.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update tomcat8' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"tomcat8-8.0.20-1.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-admin-webapps-8.0.20-1.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-docs-webapp-8.0.20-1.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-el-3.0-api-8.0.20-1.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-javadoc-8.0.20-1.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-jsp-2.3-api-8.0.20-1.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-lib-8.0.20-1.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-log4j-8.0.20-1.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-servlet-3.1-api-8.0.20-1.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat8-webapps-8.0.20-1.53.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat8 / tomcat8-admin-webapps / tomcat8-docs-webapp / etc");
}
