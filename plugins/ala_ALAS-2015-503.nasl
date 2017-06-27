#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-503.
#

include("compat.inc");

if (description)
{
  script_id(82831);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/31 04:37:06 $");

  script_cve_id("CVE-2014-8161", "CVE-2015-0241", "CVE-2015-0243", "CVE-2015-0244");
  script_xref(name:"ALAS", value:"2015-503");
  script_xref(name:"RHSA", value:"2015:0750");

  script_name(english:"Amazon Linux AMI : postgresql8 (ALAS-2015-503)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An information leak flaw was found in the way the PostgreSQL database
server handled certain error messages. An authenticated database user
could possibly obtain the results of a query they did not have
privileges to execute by observing the constraint violation error
messages produced when the query was executed. (CVE-2014-8161)

A buffer overflow flaw was found in the way PostgreSQL handled certain
numeric formatting. An authenticated database user could use a
specially crafted timestamp formatting template to cause PostgreSQL to
crash or, under certain conditions, execute arbitrary code with the
permissions of the user running PostgreSQL. (CVE-2015-0241)

A stack-buffer overflow flaw was found in PostgreSQL's pgcrypto
module. An authenticated database user could use this flaw to cause
PostgreSQL to crash or, potentially, execute arbitrary code with the
permissions of the user running PostgreSQL. (CVE-2015-0243)

A flaw was found in the way PostgreSQL handled certain errors that
were generated during protocol synchronization. An authenticated
database user could use this flaw to inject queries into an existing
connection. (CVE-2015-0244)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-503.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update postgresql8' to update your system."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql8-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/17");
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
if (rpm_check(release:"ALA", reference:"postgresql8-8.4.20-2.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-contrib-8.4.20-2.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-debuginfo-8.4.20-2.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-devel-8.4.20-2.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-docs-8.4.20-2.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-libs-8.4.20-2.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-plperl-8.4.20-2.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-plpython-8.4.20-2.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-pltcl-8.4.20-2.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-server-8.4.20-2.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-test-8.4.20-2.48.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql8 / postgresql8-contrib / postgresql8-debuginfo / etc");
}
