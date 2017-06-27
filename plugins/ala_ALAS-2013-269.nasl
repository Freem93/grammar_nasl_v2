#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-269.
#

include("compat.inc");

if (description)
{
  script_id(71581);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:48:47 $");

  script_cve_id("CVE-2013-4505", "CVE-2013-4558");
  script_xref(name:"ALAS", value:"2013-269");

  script_name(english:"Amazon Linux AMI : subversion (ALAS-2013-269)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The is_this_legal function in mod_dontdothat for Apache Subversion
1.4.0 through 1.7.13 and 1.8.0 through 1.8.4 allows remote attackers
to bypass intended access restrictions and possibly cause a denial of
service (resource consumption) via a relative URL in a REPORT request.

The get_parent_resource function in repos.c in mod_dav_svn Apache
HTTPD server module in Subversion 1.7.11 through 1.7.13 and 1.8.1
through 1.8.4, when built with assertions enabled and
SVNAutoversioning is enabled, allows remote attackers to cause a
denial of service (assertion failure and Apache process abort) via a
non-canonical URL in a request, as demonstrated using a trailing /."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-269.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update subversion' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/23");
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
if (rpm_check(release:"ALA", reference:"mod_dav_svn-1.7.14-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-1.7.14-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-debuginfo-1.7.14-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-devel-1.7.14-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-javahl-1.7.14-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-libs-1.7.14-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-perl-1.7.14-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-python-1.7.14-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-ruby-1.7.14-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-tools-1.7.14-1.36.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-debuginfo / subversion-devel / etc");
}
