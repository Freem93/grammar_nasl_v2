#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-530.
#

include("compat.inc");

if (description)
{
  script_id(83882);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/10/05 13:44:21 $");

  script_cve_id("CVE-2015-1855");
  script_xref(name:"ALAS", value:"2015-530");

  script_name(english:"Amazon Linux AMI : ruby19 (ALAS-2015-530)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"As discussed in an upstream announcement, Ruby's OpenSSL extension
suffers a vulnerability through overly permissive matching of
hostnames, which can lead to similar bugs such as CVE-2014-1492 ."
  );
  # https://www.ruby-lang.org/en/news/2015/04/13/ruby-openssl-hostname-matching-vulnerability/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?291d9038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-530.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ruby19' to update your system."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby19-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem19-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems19-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"ruby19-1.9.3.551-32.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby19-debuginfo-1.9.3.551-32.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby19-devel-1.9.3.551-32.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby19-doc-1.9.3.551-32.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby19-irb-1.9.3.551-32.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby19-libs-1.9.3.551-32.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-bigdecimal-1.1.0-32.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-io-console-0.3-32.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-json-1.5.5-32.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-minitest-2.5.1-32.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-rake-0.9.2.2-32.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem19-rdoc-3.9.5-32.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems19-1.8.23.2-32.66.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems19-devel-1.8.23.2-32.66.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby19 / ruby19-debuginfo / ruby19-devel / ruby19-doc / ruby19-irb / etc");
}
