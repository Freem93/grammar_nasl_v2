#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-802.
#

include("compat.inc");

if (description)
{
  script_id(97554);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/07 17:25:25 $");

  script_cve_id("CVE-2015-8870", "CVE-2016-5652", "CVE-2016-9533", "CVE-2016-9534", "CVE-2016-9535", "CVE-2016-9536", "CVE-2016-9537", "CVE-2016-9540");
  script_xref(name:"ALAS", value:"2017-802");

  script_name(english:"Amazon Linux AMI : libtiff / compat-libtiff3 (ALAS-2017-802)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple flaws have been discovered in libtiff. A remote attacker
could exploit these flaws to cause a crash or memory corruption and,
possibly, execute arbitrary code by tricking an application linked
against libtiff into processing specially crafted files.
(CVE-2016-9533 , CVE-2016-9534 , CVE-2016-9535)

Multiple flaws have been discovered in various libtiff tools
(tiff2pdf, tiffcrop, tiffcp, bmp2tiff). By tricking a user into
processing a specially crafted file, a remote attacker could exploit
these flaws to cause a crash or memory corruption and, possibly,
execute arbitrary code with the privileges of the user running the
libtiff tool. (CVE-2015-8870 , CVE-2016-5652 , CVE-2016-9540 ,
CVE-2016-9537 , CVE-2016-9536)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-802.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update libtiff' to update your system.

Run 'yum update compat-libtiff3' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:compat-libtiff3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:compat-libtiff3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/07");
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
if (rpm_check(release:"ALA", reference:"compat-libtiff3-3.9.4-21.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"compat-libtiff3-debuginfo-3.9.4-21.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtiff-4.0.3-27.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtiff-debuginfo-4.0.3-27.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtiff-devel-4.0.3-27.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtiff-static-4.0.3-27.29.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-libtiff3 / compat-libtiff3-debuginfo / libtiff / etc");
}
