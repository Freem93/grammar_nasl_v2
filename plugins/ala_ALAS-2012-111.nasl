#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-111.
#

include("compat.inc");

if (description)
{
  script_id(69601);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2009-5030", "CVE-2012-3358");
  script_xref(name:"ALAS", value:"2012-111");
  script_xref(name:"RHSA", value:"2012:1068");

  script_name(english:"Amazon Linux AMI : openjpeg (ALAS-2012-111)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An input validation flaw, leading to a heap-based buffer overflow, was
found in the way OpenJPEG handled the tile number and size in an image
tile header. A remote attacker could provide a specially crafted image
file that, when decoded using an application linked against OpenJPEG,
would cause the application to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application. (CVE-2012-3358)

OpenJPEG allocated insufficient memory when encoding JPEG 2000 files
from input images that have certain color depths. A remote attacker
could provide a specially crafted image file that, when opened in an
application linked against OpenJPEG (such as image_to_j2k), would
cause the application to crash or, potentially, execute arbitrary code
with the privileges of the user running the application.
(CVE-2009-5030)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-111.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openjpeg' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openjpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openjpeg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openjpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openjpeg-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/30");
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
if (rpm_check(release:"ALA", reference:"openjpeg-1.3-8.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openjpeg-debuginfo-1.3-8.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openjpeg-devel-1.3-8.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openjpeg-libs-1.3-8.5.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjpeg / openjpeg-debuginfo / openjpeg-devel / openjpeg-libs");
}
