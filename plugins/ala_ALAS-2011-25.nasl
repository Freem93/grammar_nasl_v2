#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2011-25.
#

include("compat.inc");

if (description)
{
  script_id(69584);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2011-1184", "CVE-2011-2204", "CVE-2011-3190");
  script_xref(name:"ALAS", value:"2011-25");

  script_name(english:"Amazon Linux AMI : tomcat6 (ALAS-2011-25)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Certain AJP protocol connector implementations in Apache Tomcat 7.0.0
through 7.0.20, 6.0.0 through 6.0.33, 5.5.0 through 5.5.33, and
possibly other versions allow remote attackers to spoof AJP requests,
bypass authentication, and obtain sensitive information by causing the
connector to interpret a request body as a new request.

The HTTP Digest Access Authentication implementation in Apache Tomcat
5.5.x before 5.5.34, 6.x before 6.0.33, and 7.x before 7.0.12 does not
have the expected countermeasures against replay attacks, which makes
it easier for remote attackers to bypass intended access restrictions
by sniffing the network for valid requests, related to lack of
checking of nonce (aka server nonce) and nc (aka nonce-count or client
nonce count) values.

Apache Tomcat 5.5.x before 5.5.34, 6.x before 6.0.33, and 7.x before
7.0.17, when the MemoryUserDatabase is used, creates log entries
containing passwords upon encountering errors in JMX user creation,
which allows local users to obtain sensitive information by reading a
log file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2011-25.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update tomcat6' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/02");
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
if (rpm_check(release:"ALA", reference:"tomcat6-6.0.33-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-admin-webapps-6.0.33-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-docs-webapp-6.0.33-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-el-2.1-api-6.0.33-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-javadoc-6.0.33-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-jsp-2.1-api-6.0.33-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-lib-6.0.33-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-servlet-2.5-api-6.0.33-1.26.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tomcat6-webapps-6.0.33-1.26.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat6 / tomcat6-admin-webapps / tomcat6-docs-webapp / etc");
}
