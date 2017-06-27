#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-248.
#

include("compat.inc");

if (description)
{
  script_id(71079);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:54 $");

  script_cve_id("CVE-2013-4164");
  script_xref(name:"ALAS", value:"2013-248");

  script_name(english:"Amazon Linux AMI : ruby (ALAS-2013-248)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Heap-based buffer overflow in Ruby 1.8, 1.9 before 1.9.3-p484, 2.0
before 2.0.0-p353, 2.1 before 2.1.0 preview2, and trunk before
revision 43780 allows context-dependent attackers to cause a denial of
service (segmentation fault) and possibly execute arbitrary code via a
string that is converted to a floating point value, as demonstrated
using (1) the to_f method or (2) JSON.parse."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-248.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ruby' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/26");
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
if (rpm_check(release:"ALA", reference:"ruby-1.8.7.374-2.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-debuginfo-1.8.7.374-2.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-devel-1.8.7.374-2.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-irb-1.8.7.374-2.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-libs-1.8.7.374-2.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-rdoc-1.8.7.374-2.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-ri-1.8.7.374-2.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-static-1.8.7.374-2.11.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-debuginfo / ruby-devel / ruby-irb / ruby-libs / etc");
}
