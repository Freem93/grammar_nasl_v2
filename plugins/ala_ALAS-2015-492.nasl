#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-492.
#

include("compat.inc");

if (description)
{
  script_id(81828);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/31 04:37:06 $");

  script_cve_id("CVE-2014-0067", "CVE-2014-8161", "CVE-2015-0241", "CVE-2015-0242", "CVE-2015-0243", "CVE-2015-0244");
  script_xref(name:"ALAS", value:"2015-492");

  script_name(english:"Amazon Linux AMI : postgresql92 (ALAS-2015-492)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow flaw was found in the way PostgreSQL handled certain
numeric formatting. An authenticated database user could use a
specially crafted timestamp formatting template to cause PostgreSQL to
crash or, under certain conditions, execute arbitrary code with the
permissions of the user running PostgreSQL. (CVE-2015-0241)

A buffer overflow flaw was found in the PostgreSQL's internal printf()
implementation. An authenticated database user could use a specially
crafted string in a SQL query to cause PostgreSQL to crash or,
potentially, lead to privilege escalation. (CVE-2015-0242)

A stack-buffer overflow flaw was found in PostgreSQL's pgcrypto
module. An authenticated database user could use this flaw to cause
PostgreSQL to crash or, potentially, execute arbitrary code with the
permissions of the user running PostgreSQL. (CVE-2015-0243)

A flaw was found in way PostgreSQL handled certain errors during that
were generated during protocol synchronization. An authenticated
database user could use this flaw to inject queries into an existing
connection. (CVE-2015-0244)

The 'make check' command for the test suites in PostgreSQL 9.3.3 and
earlier does not properly invoke initdb to specify the authentication
requirements for a database cluster to be used for the tests, which
allows local users to gain privileges by leveraging access to this
cluster. (CVE-2014-0067)

An information leak flaw was found in the way certain the PostgreSQL
database server handled certain error messages. An authenticated
database user could possibly obtain the results of a query they did
not have privileges to execute by observing the constraint violation
error messages produced when the query was executed. (CVE-2014-8161)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-492.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update postgresql92' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-server-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/17");
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
if (rpm_check(release:"ALA", reference:"postgresql92-9.2.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-contrib-9.2.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-debuginfo-9.2.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-devel-9.2.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-docs-9.2.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-libs-9.2.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-plperl-9.2.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-plpython-9.2.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-pltcl-9.2.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-server-9.2.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-server-compat-9.2.10-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-test-9.2.10-1.49.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql92 / postgresql92-contrib / postgresql92-debuginfo / etc");
}
