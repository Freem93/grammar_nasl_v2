#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-555.
#

include("compat.inc");

if (description)
{
  script_id(84372);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/06/25 13:16:54 $");

  script_cve_id("CVE-2014-3580", "CVE-2014-8108");
  script_xref(name:"ALAS", value:"2015-555");

  script_name(english:"Amazon Linux AMI : mod_dav_svn / subversion (ALAS-2015-555)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A NULL pointer dereference flaw was found in the way the mod_dav_svn
module handled certain requests for URIs that trigger a lookup of a
virtual transaction name. A remote, unauthenticated attacker could
send a request for a virtual transaction name that does not exist,
causing mod_dav_svn to crash. (CVE-2014-8108)

A NULL pointer dereference flaw was found in the way the mod_dav_svn
module handled REPORT requests. A remote, unauthenticated attacker
could use a specially crafted REPORT request to crash mod_dav_svn.
(CVE-2014-3580)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-555.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update subversion' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/25");
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
if (rpm_check(release:"ALA", reference:"mod24_dav_svn-1.8.11-1.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_dav_svn-1.8.11-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_dav_svn-debuginfo-1.8.11-1.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-1.8.11-1.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-debuginfo-1.8.11-1.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-devel-1.8.11-1.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-javahl-1.8.11-1.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-libs-1.8.11-1.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-perl-1.8.11-1.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-python26-1.8.11-1.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-python27-1.8.11-1.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-ruby-1.8.11-1.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-tools-1.8.11-1.50.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod24_dav_svn / mod_dav_svn / mod_dav_svn-debuginfo / subversion / etc");
}
