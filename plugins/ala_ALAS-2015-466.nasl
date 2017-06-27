#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-466.
#

include("compat.inc");

if (description)
{
  script_id(80417);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2014-8137", "CVE-2014-8138", "CVE-2014-9029");
  script_xref(name:"ALAS", value:"2015-466");
  script_xref(name:"RHSA", value:"2014:2021");

  script_name(english:"Amazon Linux AMI : jasper (ALAS-2015-466)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple off-by-one flaws, leading to heap-based buffer overflows,
were found in the way JasPer decoded JPEG 2000 image files. A
specially crafted file could cause an application using JasPer to
crash or, possibly, execute arbitrary code. (CVE-2014-9029)

A heap-based buffer overflow flaw was found in the way JasPer decoded
JPEG 2000 image files. A specially crafted file could cause an
application using JasPer to crash or, possibly, execute arbitrary
code. (CVE-2014-8138)

A double free flaw was found in the way JasPer parsed ICC color
profiles in JPEG 2000 image files. A specially crafted file could
cause an application using JasPer to crash or, possibly, execute
arbitrary code. (CVE-2014-8137)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-466.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update jasper' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jasper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jasper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jasper-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jasper-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/09");
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
if (rpm_check(release:"ALA", reference:"jasper-1.900.1-16.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"jasper-debuginfo-1.900.1-16.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"jasper-devel-1.900.1-16.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"jasper-libs-1.900.1-16.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"jasper-utils-1.900.1-16.7.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper / jasper-debuginfo / jasper-devel / jasper-libs / etc");
}
