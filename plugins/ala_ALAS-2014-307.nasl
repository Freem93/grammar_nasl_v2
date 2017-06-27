#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-307.
#

include("compat.inc");

if (description)
{
  script_id(73061);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2010-2596", "CVE-2013-1960", "CVE-2013-1961", "CVE-2013-4231", "CVE-2013-4232", "CVE-2013-4243", "CVE-2013-4244");
  script_xref(name:"ALAS", value:"2014-307");
  script_xref(name:"RHSA", value:"2014:0222");

  script_name(english:"Amazon Linux AMI : libtiff (ALAS-2014-307)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap-based buffer overflow and a use-after-free flaw were found in
the tiff2pdf tool. An attacker could use these flaws to create a
specially crafted TIFF file that would cause tiff2pdf to crash or,
possibly, execute arbitrary code. (CVE-2013-1960 , CVE-2013-4232)

Multiple buffer overflow flaws were found in the gif2tiff tool. An
attacker could use these flaws to create a specially crafted GIF file
that could cause gif2tiff to crash or, possibly, execute arbitrary
code. (CVE-2013-4231 , CVE-2013-4243 , CVE-2013-4244)

A flaw was found in the way libtiff handled OJPEG-encoded TIFF images.
An attacker could use this flaw to create a specially crafted TIFF
file that would cause an application using libtiff to crash.
(CVE-2010-2596)

Multiple buffer overflow flaws were found in the tiff2pdf tool. An
attacker could use these flaws to create a specially crafted TIFF file
that would cause tiff2pdf to crash. (CVE-2013-1961)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-307.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libtiff' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/18");
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
if (rpm_check(release:"ALA", reference:"libtiff-3.9.4-10.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtiff-debuginfo-3.9.4-10.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtiff-devel-3.9.4-10.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtiff-static-3.9.4-10.12.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff / libtiff-debuginfo / libtiff-devel / libtiff-static");
}
