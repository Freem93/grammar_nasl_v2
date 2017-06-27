#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-477.
#

include("compat.inc");

if (description)
{
  script_id(81323);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/02/13 14:50:40 $");

  script_cve_id("CVE-2014-3707", "CVE-2014-8150");
  script_xref(name:"ALAS", value:"2015-477");

  script_name(english:"Amazon Linux AMI : curl (ALAS-2015-477)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The curl_easy_duphandle function in libcurl 7.17.1 through 7.38.0,
when running with the CURLOPT_COPYPOSTFIELDS option, does not properly
copy HTTP POST data for an easy handle, which triggers an
out-of-bounds read that allows remote web servers to read sensitive
memory information. (CVE-2014-3707)

CRLF injection vulnerability in libcurl 6.0 through 7.x before 7.40.0,
when using an HTTP proxy, allows remote attackers to inject arbitrary
HTTP headers and conduct HTTP response splitting attacks via CRLF
sequences in a URL. (CVE-2014-8150)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-477.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update curl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/13");
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
if (rpm_check(release:"ALA", reference:"curl-7.40.0-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"curl-debuginfo-7.40.0-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcurl-7.40.0-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcurl-devel-7.40.0-1.49.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / libcurl / libcurl-devel");
}
