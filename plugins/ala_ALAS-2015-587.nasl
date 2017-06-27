#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-587.
#

include("compat.inc");

if (description)
{
  script_id(85632);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/26 13:32:36 $");

  script_cve_id("CVE-2015-0202", "CVE-2015-0248", "CVE-2015-0251");
  script_xref(name:"ALAS", value:"2015-587");

  script_name(english:"Amazon Linux AMI : subversion / mod_dav_svn (ALAS-2015-587)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The mod_dav_svn server in Subversion 1.8.0 through 1.8.11 allows
remote attackers to cause a denial of service (memory consumption) via
a large number of REPORT requests, which trigger the traversal of FSFS
repository nodes. (CVE-2015-0202)

An assertion failure flaw was found in the way the SVN server
processed certain requests with dynamically evaluated revision
numbers. A remote attacker could use this flaw to cause the SVN server
(both svnserve and httpd with the mod_dav_svn module) to crash.
(CVE-2015-0248)

It was found that the mod_dav_svn module did not properly validate the
svn:author property of certain requests. An attacker able to create
new revisions could use this flaw to spoof the svn:author property.
(CVE-2015-0251)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-587.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update subversion mod_dav_svn' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_dav_svn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/26");
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
if (rpm_check(release:"ALA", reference:"mod24_dav_svn-1.8.13-7.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_dav_svn-1.8.13-7.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_dav_svn-debuginfo-1.8.13-7.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-1.8.13-7.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-debuginfo-1.8.13-7.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-devel-1.8.13-7.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-javahl-1.8.13-7.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-libs-1.8.13-7.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-perl-1.8.13-7.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-python26-1.8.13-7.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-python27-1.8.13-7.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-ruby-1.8.13-7.52.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-tools-1.8.13-7.52.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod24_dav_svn / mod_dav_svn / mod_dav_svn-debuginfo / subversion / etc");
}
