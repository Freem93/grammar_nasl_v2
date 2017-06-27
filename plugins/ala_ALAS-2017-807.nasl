#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-807.
#

include("compat.inc");

if (description)
{
  script_id(97897);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/23 13:29:51 $");

  script_cve_id("CVE-2016-5139", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-7163", "CVE-2016-9675");
  script_xref(name:"ALAS", value:"2017-807");

  script_name(english:"Amazon Linux AMI : openjpeg (ALAS-2017-807)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in OpenJPEG. A specially crafted JPEG2000 image
could cause an application using OpenJPEG to crash or, potentially,
execute arbitrary code. (CVE-2016-5139 , CVE-2016-5158 , CVE-2016-5159
, CVE-2016-7163)

A vulnerability was found in the patch for CVE-2013-6045 for OpenJPEG.
A specially crafted JPEG2000 image, when read by an application using
OpenJPEG, could cause heap-based buffer overflows leading to a crash
or, potentially, arbitrary code execution. (CVE-2016-9675)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-807.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openjpeg' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openjpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openjpeg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openjpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openjpeg-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"openjpeg-1.3-16.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openjpeg-debuginfo-1.3-16.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openjpeg-devel-1.3-16.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openjpeg-libs-1.3-16.9.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjpeg / openjpeg-debuginfo / openjpeg-devel / openjpeg-libs");
}
