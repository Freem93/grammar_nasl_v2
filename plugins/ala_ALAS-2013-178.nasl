#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-178.
#

include("compat.inc");

if (description)
{
  script_id(69737);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2013-1899", "CVE-2013-1900", "CVE-2013-1901");
  script_xref(name:"ALAS", value:"2013-178");

  script_name(english:"Amazon Linux AMI : postgresql9 (ALAS-2013-178)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Argument injection vulnerability in PostgreSQL 9.2.x before 9.2.4,
9.1.x before 9.1.9, and 9.0.x before 9.0.13 allows remote attackers to
cause a denial of service (file corruption), and allows remote
authenticated users to modify configuration settings and execute
arbitrary code, via a connection request using a database name that
begins with a '-' (hyphen).

PostgreSQL 9.2.x before 9.2.4 and 9.1.x before 9.1.9 does not properly
check REPLICATION privileges, which allows remote authenticated users
to bypass intended backup restrictions by calling the (1)
pg_start_backup or (2) pg_stop_backup functions.

PostgreSQL 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before
9.0.13, and 8.4.x before 8.4.17, when using OpenSSL, generates
insufficiently random numbers, which might allow remote authenticated
users to have an unspecified impact via vectors related to the
'contrib/pgcrypto functions.'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-178.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update postgresql9' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/04");
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
if (rpm_check(release:"ALA", reference:"postgresql9-9.2.4-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-contrib-9.2.4-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-debuginfo-9.2.4-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-devel-9.2.4-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-docs-9.2.4-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-libs-9.2.4-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-plperl-9.2.4-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-plpython-9.2.4-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-pltcl-9.2.4-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-server-9.2.4-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-test-9.2.4-1.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql9-upgrade-9.2.4-1.35.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql9 / postgresql9-contrib / postgresql9-debuginfo / etc");
}
