#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-173.
#

include("compat.inc");

if (description)
{
  script_id(69732);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2011-1005", "CVE-2012-4481", "CVE-2013-1821");
  script_xref(name:"ALAS", value:"2013-173");
  script_xref(name:"RHSA", value:"2013:0612");

  script_name(english:"Amazon Linux AMI : ruby (ALAS-2013-173)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Ruby's REXML library did not properly restrict
XML entity expansion. An attacker could use this flaw to cause a
denial of service by tricking a Ruby application using REXML to read
text nodes from specially crafted XML content, which will result in
REXML consuming large amounts of system memory. (CVE-2013-1821)

It was found that the RHSA-2011-0910 update did not correctly fix the
CVE-2011-1005 issue, a flaw in the method for translating an exception
message into a string in the Exception class. A remote attacker could
use this flaw to bypass safe level 4 restrictions, allowing untrusted
(tainted) code to modify arbitrary, trusted (untainted) strings, which
safe level 4 restrictions would otherwise prevent. (CVE-2012-4481)

The safe-level feature in Ruby 1.8.6 through 1.8.6-420, 1.8.7 through
1.8.7-330, and 1.8.8dev allows context-dependent attackers to modify
strings via the Exception#to_s method, as demonstrated by changing an
intended pathname. (CVE-2011-1005)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-173.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ruby' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
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
if (rpm_check(release:"ALA", reference:"ruby-1.8.7.371-2.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-debuginfo-1.8.7.371-2.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-devel-1.8.7.371-2.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-irb-1.8.7.371-2.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-libs-1.8.7.371-2.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-rdoc-1.8.7.371-2.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-ri-1.8.7.371-2.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby-static-1.8.7.371-2.25.amzn1")) flag++;

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
