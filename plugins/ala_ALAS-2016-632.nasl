#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-632.
#

include("compat.inc");

if (description)
{
  script_id(87966);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2015-7551");
  script_xref(name:"ALAS", value:"2016-632");

  script_name(english:"Amazon Linux AMI : ruby19 / ruby20,ruby21,ruby22 (ALAS-2016-632)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"DL::dlopen could open a library with tainted library name even if
$SAFE > 0."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-632.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update ruby19' to update your system.

Run 'yum update ruby20' to update your system.

Run 'yum update ruby21' to update your system.

Run 'yum update ruby22' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby22-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby22-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby22-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby22-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby22-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem20-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem20-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem20-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem21-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem21-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem21-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem22-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem22-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem22-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems19-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems20-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems21-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems22-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/19");
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
if (rpm_check(release:"ALA", reference:"ruby19-1.9.3.551-32.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby19-debuginfo-1.9.3.551-32.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby19-devel-1.9.3.551-32.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby19-doc-1.9.3.551-32.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby19-irb-1.9.3.551-32.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby19-libs-1.9.3.551-32.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-2.0.0.648-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-debuginfo-2.0.0.648-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-devel-2.0.0.648-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-doc-2.0.0.648-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-irb-2.0.0.648-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-libs-2.0.0.648-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby21-2.1.8-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby21-debuginfo-2.1.8-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby21-devel-2.1.8-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby21-doc-2.1.8-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby21-irb-2.1.8-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby21-libs-2.1.8-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-2.2.4-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-debuginfo-2.2.4-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-devel-2.2.4-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-doc-2.2.4-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-irb-2.2.4-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby22-libs-2.2.4-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-bigdecimal-1.1.0-32.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-io-console-0.3-32.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-json-1.5.5-32.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-minitest-2.5.1-32.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-rake-0.9.2.2-32.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-rdoc-3.9.5-32.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem20-bigdecimal-1.2.0-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem20-io-console-0.4.2-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem20-psych-2.0.0-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem21-bigdecimal-1.2.4-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem21-io-console-0.4.3-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem21-psych-2.0.5-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem22-bigdecimal-1.2.6-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem22-io-console-0.4.3-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem22-psych-2.0.8-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems19-1.8.23.2-32.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems19-devel-1.8.23.2-32.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems20-2.0.14.1-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems20-devel-2.0.14.1-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems21-2.2.5-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems21-devel-2.2.5-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems22-2.4.5.1-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems22-devel-2.4.5.1-1.8.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby19 / ruby19-debuginfo / ruby19-devel / ruby19-doc / ruby19-irb / etc");
}
