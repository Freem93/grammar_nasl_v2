#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-353.
#

include("compat.inc");

if (description)
{
  script_id(78296);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2013-7038", "CVE-2013-7039");
  script_xref(name:"ALAS", value:"2014-353");

  script_name(english:"Amazon Linux AMI : libmicrohttpd (ALAS-2014-353)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stack-based buffer overflow in the MHD_digest_auth_check function in
libmicrohttpd before 0.9.32, when MHD_OPTION_CONNECTION_MEMORY_LIMIT
is set to a large value, allows remote attackers to cause a denial of
service (crash) or possibly execute arbitrary code via a long URI in
an authentication header.

The MHD_http_unescape function in libmicrohttpd before 0.9.32 might
allow remote attackers to obtain sensitive information or cause a
denial of service (crash) via unspecified vectors that trigger an
out-of-bounds read."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-353.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libmicrohttpd' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libmicrohttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libmicrohttpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libmicrohttpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libmicrohttpd-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"libmicrohttpd-0.9.33-2.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libmicrohttpd-debuginfo-0.9.33-2.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libmicrohttpd-devel-0.9.33-2.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libmicrohttpd-doc-0.9.33-2.3.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmicrohttpd / libmicrohttpd-debuginfo / libmicrohttpd-devel / etc");
}
