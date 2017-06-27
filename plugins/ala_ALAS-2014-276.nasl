#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-276.
#

include("compat.inc");

if (description)
{
  script_id(72294);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:48:47 $");

  script_cve_id("CVE-2013-0345", "CVE-2013-4484");
  script_xref(name:"ALAS", value:"2014-276");

  script_name(english:"Amazon Linux AMI : varnish (ALAS-2014-276)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Varnish before 3.0.5 allows remote attackers to cause a denial of
service (child-process crash and temporary caching outage) via a GET
request with trailing whitespace characters and no URI.

varnish 3.0.3 uses world-readable permissions for the
/var/log/varnish/ directory and the log files in the directory, which
allows local users to obtain sensitive information by reading the
files. NOTE: some of these details are obtained from third party
information."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-276.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update varnish' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:varnish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:varnish-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:varnish-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:varnish-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:varnish-libs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");
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
if (rpm_check(release:"ALA", reference:"varnish-3.0.5-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"varnish-debuginfo-3.0.5-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"varnish-docs-3.0.5-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"varnish-libs-3.0.5-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"varnish-libs-devel-3.0.5-1.14.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "varnish / varnish-debuginfo / varnish-docs / varnish-libs / etc");
}
