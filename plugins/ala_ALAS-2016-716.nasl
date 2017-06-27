#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-716.
#

include("compat.inc");

if (description)
{
  script_id(91768);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2015-8895", "CVE-2015-8896", "CVE-2015-8897", "CVE-2015-8898", "CVE-2016-5118", "CVE-2016-5239", "CVE-2016-5240");
  script_xref(name:"ALAS", value:"2016-716");

  script_name(english:"Amazon Linux AMI : ImageMagick (ALAS-2016-716)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that ImageMagick did not properly sanitize certain
input before using it to invoke processes. A remote attacker could
create a specially crafted image that, when processed by an
application using ImageMagick or an unsuspecting user using the
ImageMagick utilities, would lead to arbitrary execution of shell
commands with the privileges of the user running the application.
(CVE-2016-5118)

It was discovered that ImageMagick did not properly sanitize certain
input before passing it to the gnuplot delegate functionality. A
remote attacker could create a specially crafted image that, when
processed by an application using ImageMagick or an unsuspecting user
using the ImageMagick utilities, would lead to arbitrary execution of
shell commands with the privileges of the user running the
application. (CVE-2016-5239)

Multiple flaws have been discovered in ImageMagick. A remote attacker
could, for example, create specially crafted images that, when
processed by an application using ImageMagick or an unsuspecting user
using the ImageMagick utilities, would result in a memory corruption
and, potentially, execution of arbitrary code, a denial of service, or
an application crash. (CVE-2015-8896 , CVE-2015-8895 , CVE-2016-5240 ,
CVE-2015-8897 , CVE-2015-8898)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-716.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ImageMagick' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"ImageMagick-6.7.8.9-15.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-c++-6.7.8.9-15.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-c++-devel-6.7.8.9-15.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-debuginfo-6.7.8.9-15.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-devel-6.7.8.9-15.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-doc-6.7.8.9-15.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ImageMagick-perl-6.7.8.9-15.21.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
}
