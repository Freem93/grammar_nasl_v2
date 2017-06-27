#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-96.
#

include("compat.inc");

if (description)
{
  script_id(69703);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2010-3294");
  script_xref(name:"ALAS", value:"2012-96");
  script_xref(name:"RHSA", value:"2012:0811");

  script_name(english:"Amazon Linux AMI : php-pecl-apc (ALAS-2012-96)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A cross-site scripting (XSS) flaw was found in the 'apc.php' script,
which provides a detailed analysis of the internal workings of APC and
is shipped as part of the APC extension documentation. A remote
attacker could possibly use this flaw to conduct a cross-site
scripting attack. (CVE-2010-3294)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-96.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update php-pecl-apc' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pecl-apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pecl-apc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pecl-apc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/05");
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
if (rpm_check(release:"ALA", reference:"php-pecl-apc-3.1.10-1.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-pecl-apc-debuginfo-3.1.10-1.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-pecl-apc-devel-3.1.10-1.4.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-pecl-apc / php-pecl-apc-debuginfo / php-pecl-apc-devel");
}
