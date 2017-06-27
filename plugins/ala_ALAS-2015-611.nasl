#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-611.
#

include("compat.inc");

if (description)
{
  script_id(87015);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/03/21 15:01:55 $");

  script_cve_id("CVE-2015-8126");
  script_xref(name:"ALAS", value:"2015-611");

  script_name(english:"Amazon Linux AMI : libpng (ALAS-2015-611)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple buffer overflows in the png_set_PLTE and png_get_PLTE
functions in libpng before 1.0.64, 1.1.x and 1.2.x before 1.2.54,
1.3.x and 1.4.x before 1.4.17, 1.5.x before 1.5.24, and 1.6.x before
1.6.19, allowing remote attackers to cause a denial of service
(application crash) or possibly have unspecified other impact via a
small bit-depth value in an IHDR (aka image header) chunk in a PNG
image (CVE-2015-8126)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-611.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libpng' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libpng-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libpng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libpng-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"libpng-1.2.49-1.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libpng-debuginfo-1.2.49-1.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libpng-devel-1.2.49-1.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libpng-static-1.2.49-1.13.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng / libpng-debuginfo / libpng-devel / libpng-static");
}
