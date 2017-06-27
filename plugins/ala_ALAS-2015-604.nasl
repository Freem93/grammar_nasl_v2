#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-604.
#

include("compat.inc");

if (description)
{
  script_id(86635);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2007-0455", "CVE-2007-2756", "CVE-2007-3472", "CVE-2007-3473", "CVE-2009-3546", "CVE-2015-0848", "CVE-2015-4588", "CVE-2015-4695", "CVE-2015-4696");
  script_xref(name:"ALAS", value:"2015-604");
  script_xref(name:"RHSA", value:"2015:1917");

  script_name(english:"Amazon Linux AMI : libwmf (ALAS-2015-604)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that libwmf did not correctly process certain WMF
(Windows Metafiles) with embedded BMP images. By tricking a victim
into opening a specially crafted WMF file in an application using
libwmf, a remote attacker could possibly use this flaw to execute
arbitrary code with the privileges of the user running the
application. (CVE-2015-0848 , CVE-2015-4588)

It was discovered that libwmf did not properly process certain WMF
files. By tricking a victim into opening a specially crafted WMF file
in an application using libwmf, a remote attacker could possibly
exploit this flaw to cause a crash or execute arbitrary code with the
privileges of the user running the application. (CVE-2015-4696)

It was discovered that libwmf did not properly process certain WMF
files. By tricking a victim into opening a specially crafted WMF file
in an application using libwmf, a remote attacker could possibly
exploit this flaw to cause a crash. (CVE-2015-4695)

The gdPngReadData function in libgd 2.0.34 allows user-assisted
attackers to cause a denial of service (CPU consumption) via a crafted
PNG image with truncated data, which causes an infinite loop in the
png_read_info function in libpng. (CVE-2007-2756)

Buffer overflow in the gdImageStringFTEx function in gdft.c in GD
Graphics Library 2.0.33 and earlier allows remote attackers to cause a
denial of service (application crash) and possibly execute arbitrary
code via a crafted string with a JIS encoded font. (CVE-2007-0455)

The _gdGetColors function in gd_gd.c in PHP 5.2.11 and 5.3.x before
5.3.1, and the GD Graphics Library 2.x, does not properly verify a
certain colorsTotal structure member, which might allow remote
attackers to conduct buffer overflow or buffer over-read attacks via a
crafted GD file, a different vulnerability than CVE-2009-3293 . NOTE:
some of these details are obtained from third party information.
(CVE-2009-3546)

Integer overflow in gdImageCreateTrueColor function in the GD Graphics
Library (libgd) before 2.0.35 allows user-assisted remote attackers to
have unspecified attack vectors and impact. (CVE-2007-3472)

The gdImageCreateXbm function in the GD Graphics Library (libgd)
before 2.0.35 allows user-assisted remote attackers to cause a denial
of service (crash) via unspecified vectors involving a gdImageCreate
failure. (CVE-2007-3473)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-604.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libwmf' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwmf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwmf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwmf-lite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/29");
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
if (rpm_check(release:"ALA", reference:"libwmf-0.2.8.4-41.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libwmf-debuginfo-0.2.8.4-41.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libwmf-devel-0.2.8.4-41.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libwmf-lite-0.2.8.4-41.11.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwmf / libwmf-debuginfo / libwmf-devel / libwmf-lite");
}
