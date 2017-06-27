#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-514.
#

include("compat.inc");

if (description)
{
  script_id(83057);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/11/06 14:51:12 $");

  script_cve_id("CVE-2015-3143", "CVE-2015-3144", "CVE-2015-3145", "CVE-2015-3148");
  script_xref(name:"ALAS", value:"2015-514");

  script_name(english:"Amazon Linux AMI : curl (ALAS-2015-514)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that libcurl could incorrectly reuse
NTLM-authenticated connections for subsequent unauthenticated requests
to the same host. If an application using libcurl established an
NTLM-authenticated connection to a server, and sent subsequent
unauthenticed requests to the same server, the unauthenticated
requests could be sent over the NTLM-authenticated connection,
appearing as if they were sent by the NTLM authenticated user.
(CVE-2015-3143)

It was discovered that libcurl could incorrectly reuse Negotiate
authenticated HTTP connections for subsequent requests. If an
application using libcurl established a Negotiate authenticated HTTP
connection to a server and sent subsequent requests with different
credentials, the connection could be re-used with the initial set of
credentials instead of using the new ones. (CVE-2015-3148)

It was discovered that libcurl did not properly process cookies with a
specially crafted 'path' element. If an application using libcurl
connected to a malicious HTTP server sending specially crafted
'Set-Cookies' headers, this could lead to an out-of-bounds read, and
possibly cause that application to crash. (CVE-2015-3145)

It was discovered that libcurl did not properly process zero-length
host names. If an attacker could trick an application using libcurl
into processing zero-length host names, this could lead to an
out-of-bounds read, and possibly cause that application to crash.
(CVE-2015-3144)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-514.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update curl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/27");
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
if (rpm_check(release:"ALA", reference:"curl-7.40.0-3.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"curl-debuginfo-7.40.0-3.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcurl-7.40.0-3.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcurl-devel-7.40.0-3.50.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / libcurl / libcurl-devel");
}
