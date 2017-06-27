#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-284.
#

include("compat.inc");

if (description)
{
  script_id(72302);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2014-0978");
  script_xref(name:"ALAS", value:"2014-284");

  script_name(english:"Amazon Linux AMI : graphviz (ALAS-2014-284)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stack-based buffer overflow in the yyerror function in
lib/cgraph/scan.l in Graphviz 2.34.0 allows remote attackers to have
unspecified impact via a long line in a dot file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-284.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update graphviz' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-R");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-graphs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-php54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");
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
if (rpm_check(release:"ALA", reference:"graphviz-2.30.1-6.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-R-2.30.1-6.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-debuginfo-2.30.1-6.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-devel-2.30.1-6.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-doc-2.30.1-6.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-gd-2.30.1-6.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-graphs-2.30.1-6.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-guile-2.30.1-6.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-java-2.30.1-6.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-lua-2.30.1-6.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-perl-2.30.1-6.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-php54-2.30.1-6.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-python-2.30.1-6.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-ruby-2.30.1-6.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-tcl-2.30.1-6.30.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "graphviz / graphviz-R / graphviz-debuginfo / graphviz-devel / etc");
}
