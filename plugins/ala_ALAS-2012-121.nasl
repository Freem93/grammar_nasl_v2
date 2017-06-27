#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-121.
#

include("compat.inc");

if (description)
{
  script_id(69611);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2012-3488");
  script_xref(name:"ALAS", value:"2012-121");

  script_name(english:"Amazon Linux AMI : postgresql9 (ALAS-2012-121)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The libxslt support in contrib/xml2 in PostgreSQL 8.3 before 8.3.20,
8.4 before 8.4.13, 9.0 before 9.0.9, and 9.1 before 9.1.5 does not
properly restrict access to files and URLs, which allows remote
authenticated users to modify data, obtain sensitive information, or
trigger outbound traffic to arbitrary external hosts by leveraging (1)
stylesheet commands that are permitted by the libxslt security options
or (2) an xslt_process feature, related to an XML External Entity (aka
XXE) issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-121.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update postgresql9' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql9-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql9-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql9-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql9-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql9-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql9-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql9-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql9-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql9-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/04");
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
if (rpm_check(release:"ALA", reference:"postgresql9-9.1.5-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-contrib-9.1.5-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-debuginfo-9.1.5-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-devel-9.1.5-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-docs-9.1.5-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-libs-9.1.5-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-plperl-9.1.5-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-plpython-9.1.5-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-pltcl-9.1.5-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-server-9.1.5-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-test-9.1.5-1.23.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql9 / postgresql9-contrib / postgresql9-debuginfo / etc");
}
