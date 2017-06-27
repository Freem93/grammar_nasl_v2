#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-231.
#

include("compat.inc");

if (description)
{
  script_id(70567);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:54 $");

  script_cve_id("CVE-2013-4363");
  script_xref(name:"ALAS", value:"2013-231");

  script_name(english:"Amazon Linux AMI : rubygems (ALAS-2013-231)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Algorithmic complexity vulnerability in
Gem::Version::ANCHORED_VERSION_PATTERN in lib/rubygems/version.rb in
RubyGems before 1.8.23.2, 1.8.24 through 1.8.26, 2.0.x before 2.0.10,
and 2.1.x before 2.1.5, as used in Ruby 1.9.0 through 2.0.0p247,
allows remote attackers to cause a denial of service (CPU consumption)
via a crafted gem version that triggers a large amount of backtracking
in a regular expression. NOTE: this issue is due to an incomplete fix
for CVE-2013-4287 ."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-231.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update rubygems' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/24");
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
if (rpm_check(release:"ALA", reference:"rubygems-1.8.25-8.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems-devel-1.8.25-8.12.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rubygems / rubygems-devel");
}
