#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-306.
#

include("compat.inc");

if (description)
{
  script_id(73060);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/02/18 15:00:16 $");

  script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066");
  script_xref(name:"ALAS", value:"2014-306");
  script_xref(name:"RHSA", value:"2014:0211");

  script_name(english:"Amazon Linux AMI : postgresql9 (ALAS-2014-306)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple stack-based buffer overflow flaws were found in the date/time
implementation of PostgreSQL. An authenticated database user could
provide a specially crafted date/time value that, when processed,
could cause PostgreSQL to crash or, potentially, execute arbitrary
code with the permissions of the user running PostgreSQL.
(CVE-2014-0063)

Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in various type input functions in PostgreSQL.
An authenticated database user could possibly use these flaws to crash
PostgreSQL or, potentially, execute arbitrary code with the
permissions of the user running PostgreSQL. (CVE-2014-0064)

Multiple potential buffer overflow flaws were found in PostgreSQL. An
authenticated database user could possibly use these flaws to crash
PostgreSQL or, potentially, execute arbitrary code with the
permissions of the user running PostgreSQL. (CVE-2014-0065)

It was found that granting a SQL role to a database user in a
PostgreSQL database without specifying the 'ADMIN' option allowed the
grantee to remove other users from their granted role. An
authenticated database user could use this flaw to remove a user from
a SQL role which they were granted access to. (CVE-2014-0060)

A flaw was found in the validator functions provided by PostgreSQL's
procedural languages (PLs). An authenticated database user could
possibly use this flaw to escalate their privileges. (CVE-2014-0061)

A race condition was found in the way the CREATE INDEX command
performed multiple independent lookups of a table that had to be
indexed. An authenticated database user could possibly use this flaw
to escalate their privileges. (CVE-2014-0062)

It was found that the chkpass extension of PostgreSQL did not check
the return value of the crypt() function. An authenticated database
user could possibly use this flaw to crash PostgreSQL via a NULL
pointer dereference. (CVE-2014-0066)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-306.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update postgresql9' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql9-upgrade");
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
if (rpm_check(release:"ALA", reference:"postgresql9-9.2.7-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-contrib-9.2.7-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-debuginfo-9.2.7-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-devel-9.2.7-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-docs-9.2.7-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-libs-9.2.7-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-plperl-9.2.7-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-plpython-9.2.7-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-pltcl-9.2.7-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-server-9.2.7-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-test-9.2.7-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-upgrade-9.2.7-1.40.amzn1")) flag++;

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
