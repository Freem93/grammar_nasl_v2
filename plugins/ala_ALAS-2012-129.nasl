#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-129.
#

include("compat.inc");

if (description)
{
  script_id(69619);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2012-3488", "CVE-2012-3489");
  script_xref(name:"ALAS", value:"2012-129");
  script_xref(name:"RHSA", value:"2012:1263");

  script_name(english:"Amazon Linux AMI : postgresql8 (ALAS-2012-129)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the optional PostgreSQL xml2 contrib module allowed
local files and remote URLs to be read and written to with the
privileges of the database server when parsing Extensible Stylesheet
Language Transformations (XSLT). An unprivileged database user could
use this flaw to read and write to local files (such as the database's
configuration files) and remote URLs they would otherwise not have
access to by issuing a specially crafted SQL query. (CVE-2012-3488)

It was found that the 'xml' data type allowed local files and remote
URLs to be read with the privileges of the database server to resolve
DTD and entity references in the provided XML. An unprivileged
database user could use this flaw to read local files they would
otherwise not have access to by issuing a specially crafted SQL query.
Note that the full contents of the files were not returned, but
portions could be displayed to the user via error messages.
(CVE-2012-3489)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-129.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update postgresql8' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/22");
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
if (rpm_check(release:"ALA", reference:"postgresql8-8.4.13-1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-contrib-8.4.13-1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-debuginfo-8.4.13-1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-devel-8.4.13-1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-docs-8.4.13-1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-libs-8.4.13-1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-plperl-8.4.13-1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-plpython-8.4.13-1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-pltcl-8.4.13-1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-server-8.4.13-1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql8-test-8.4.13-1.37.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql8 / postgresql8-contrib / postgresql8-debuginfo / etc");
}
