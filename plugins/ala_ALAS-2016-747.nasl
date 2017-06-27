#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-747.
#

include("compat.inc");

if (description)
{
  script_id(93539);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/05/19 14:17:02 $");

  script_cve_id("CVE-2016-5423", "CVE-2016-5424");
  script_xref(name:"ALAS", value:"2016-747");

  script_name(english:"Amazon Linux AMI : postgresql92 / postgresql93,postgresql94 (ALAS-2016-747)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way PostgreSQL server handled certain SQL
statements containing CASE/WHEN commands. A remote, authenticated
attacker could use a specially crafted SQL statement to cause
PostgreSQL to crash or disclose a few bytes of server memory or
possibly execute arbitrary code. (CVE-2016-5423)

A flaw was found in the way PostgreSQL client programs handled
database and role names containing newlines, carriage returns, double
quotes, or backslashes. By crafting such an object name, roles with
the CREATEDB or CREATEROLE option could escalate their privileges to
superuser when a superuser next executes maintenance with a vulnerable
client program. (CVE-2016-5424)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-747.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update postgresql92' to update your system.

Run 'yum update postgresql93' to update your system.

Run 'yum update postgresql94' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-plpython26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-plpython27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-server-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql92-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-plpython26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-plpython27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-plpython26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-plpython27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"postgresql92-9.2.18-1.59.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-contrib-9.2.18-1.59.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-debuginfo-9.2.18-1.59.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-devel-9.2.18-1.59.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-docs-9.2.18-1.59.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-libs-9.2.18-1.59.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-plperl-9.2.18-1.59.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-plpython26-9.2.18-1.59.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-plpython27-9.2.18-1.59.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-pltcl-9.2.18-1.59.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-server-9.2.18-1.59.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-server-compat-9.2.18-1.59.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql92-test-9.2.18-1.59.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-9.3.14-1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-contrib-9.3.14-1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-debuginfo-9.3.14-1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-devel-9.3.14-1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-docs-9.3.14-1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-libs-9.3.14-1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-plperl-9.3.14-1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-plpython26-9.3.14-1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-plpython27-9.3.14-1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-pltcl-9.3.14-1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-server-9.3.14-1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-test-9.3.14-1.62.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-9.4.9-1.67.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-contrib-9.4.9-1.67.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-debuginfo-9.4.9-1.67.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-devel-9.4.9-1.67.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-docs-9.4.9-1.67.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-libs-9.4.9-1.67.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-plperl-9.4.9-1.67.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-plpython26-9.4.9-1.67.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-plpython27-9.4.9-1.67.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-server-9.4.9-1.67.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-test-9.4.9-1.67.amzn1")) flag++;

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
