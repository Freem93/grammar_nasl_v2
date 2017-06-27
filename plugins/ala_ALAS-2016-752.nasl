#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-752.
#

include("compat.inc");

if (description)
{
  script_id(94018);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/02/13 20:44:58 $");

  script_cve_id("CVE-2016-7446", "CVE-2016-7447", "CVE-2016-7448", "CVE-2016-7449");
  script_xref(name:"ALAS", value:"2016-752");

  script_name(english:"Amazon Linux AMI : GraphicsMagick (ALAS-2016-752)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A possible heap overflow was discovered in the EscapeParenthesis()
function (CVE-2016-7447).

Various issues were found in the processing of SVG files in
GraphicsMagick (CVE-2016-7446).

The TIFF reader had a bug pertaining to use of TIFFGetField() when a
'count' value is returned. The bug caused a heap read overflow (due to
using strlcpy() to copy a possibly unterminated string) which could
allow an untrusted file to crash the software (CVE-2016-7449).

The Utah RLE reader did not validate that header information was
reasonable given the file size and so it could cause huge memory
allocations and/or consume huge amounts of CPU, causing a denial of
service (CVE-2016-7448)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-752.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update GraphicsMagick' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:GraphicsMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:GraphicsMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:GraphicsMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:GraphicsMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:GraphicsMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"GraphicsMagick-1.3.25-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"GraphicsMagick-c++-1.3.25-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"GraphicsMagick-c++-devel-1.3.25-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"GraphicsMagick-debuginfo-1.3.25-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"GraphicsMagick-devel-1.3.25-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"GraphicsMagick-doc-1.3.25-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"GraphicsMagick-perl-1.3.25-1.9.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GraphicsMagick / GraphicsMagick-c++ / GraphicsMagick-c++-devel / etc");
}
