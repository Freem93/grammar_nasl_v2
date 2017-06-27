#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-365.
#

include("compat.inc");

if (description)
{
  script_id(78308);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2013-4231", "CVE-2013-4232", "CVE-2013-4243", "CVE-2013-4244");
  script_xref(name:"ALAS", value:"2014-365");

  script_name(english:"Amazon Linux AMI : libtiff (ALAS-2014-365)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Use-after-free vulnerability in the t2p_readwrite_pdf_image function
in tools/tiff2pdf.c in libtiff 4.0.3 allows remote attackers to cause
a denial of service (crash) or possible execute arbitrary code via a
crafted TIFF image.

The LZW decompressor in the gif2tiff tool in libtiff 4.0.3 and earlier
allows context-dependent attackers to cause a denial of service
(out-of-bounds write and crash) or possibly execute arbitrary code via
a crafted GIF image.

Heap-based buffer overflow in the readgifimage function in the
gif2tiff tool in libtiff 4.0.3 and earlier allows remote attackers to
cause a denial of service (crash) and possibly execute arbitrary code
via a crafted height and width values in a GIF image.

Multiple buffer overflows in libtiff before 4.0.3 allow remote
attackers to cause a denial of service (out-of-bounds write) via a
crafted (1) extension block in a GIF image or (2) GIF raster image to
tools/gif2tiff.c or (3) a long filename for a TIFF image to
tools/rgb2ycbcr.c. NOTE: vectors 1 and 3 are disputed by Red Hat,
which states that the input cannot exceed the allocated buffer size."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-365.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libtiff' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/26");
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
if (rpm_check(release:"ALA", reference:"libtiff-4.0.3-15.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtiff-debuginfo-4.0.3-15.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtiff-devel-4.0.3-15.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtiff-static-4.0.3-15.19.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff / libtiff-debuginfo / libtiff-devel / libtiff-static");
}
