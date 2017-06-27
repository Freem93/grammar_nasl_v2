#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-53.
#

include("compat.inc");

if (description)
{
  script_id(69660);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2012-1053", "CVE-2012-1054");
  script_xref(name:"ALAS", value:"2012-53");

  script_name(english:"Amazon Linux AMI : puppet (ALAS-2012-53)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Puppet 2.6.x before 2.6.14 and 2.7.x before 2.7.11, and Puppet
Enterprise (PE) Users 1.0, 1.1, 1.2.x, 2.0.x before 2.0.3, when
managing a user login file with the k5login resource type, allows
local users to gain privileges via a symlink attack on .k5login.

The change_user method in the SUIDManager
(lib/puppet/util/suidmanager.rb) in Puppet 2.6.x before 2.6.14 and
2.7.x before 2.7.11, and Puppet Enterprise (PE) Users 1.0, 1.1, 1.2.x,
2.0.x before 2.0.3 does not properly manage group privileges, which
allows local users to gain privileges via vectors related to (1) the
change_user not dropping supplementary groups in certain conditions,
(2) changes to the eguid without associated changes to the egid, or
(3) the addition of the real gid to supplementary groups."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-53.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update puppet' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:puppet-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:puppet-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/15");
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
if (rpm_check(release:"ALA", reference:"puppet-2.6.14-1.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"puppet-debuginfo-2.6.14-1.5.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"puppet-server-2.6.14-1.5.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "puppet / puppet-debuginfo / puppet-server");
}
