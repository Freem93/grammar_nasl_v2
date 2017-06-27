#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-318.
#

include("compat.inc");

if (description)
{
  script_id(73237);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2014-0032");
  script_xref(name:"ALAS", value:"2014-318");

  script_name(english:"Amazon Linux AMI : subversion (ALAS-2014-318)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way the mod_dav_svn module handled OPTIONS
requests. A remote attacker with read access to an SVN repository
served via HTTP could use this flaw to cause the httpd process that
handled such a request to crash.

The get_resource function in repos.c in the mod_dav_svn module in
Apache Subversion before 1.7.15 and 1.8.x before 1.8.6, when
SVNListParentPath is enabled, allows remote attackers to cause a
denial of service (crash) via vectors related to the server root and
request methods other than GET, as demonstrated by the 'svn ls
http://svn.example.com' command."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-318.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update subversion' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/28");
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
if (rpm_check(release:"ALA", reference:"mod_dav_svn-1.8.8-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-1.8.8-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-debuginfo-1.8.8-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-devel-1.8.8-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-javahl-1.8.8-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-libs-1.8.8-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-perl-1.8.8-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-python-1.8.8-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-ruby-1.8.8-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-tools-1.8.8-1.42.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-debuginfo / subversion-devel / etc");
}
