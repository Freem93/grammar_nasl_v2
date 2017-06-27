#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-456.
#

include("compat.inc");

if (description)
{
  script_id(79840);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2014-3248");
  script_xref(name:"ALAS", value:"2014-456");

  script_name(english:"Amazon Linux AMI : facter (ALAS-2014-456)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Untrusted search path vulnerability in Puppet Enterprise 2.8 before
2.8.7, Puppet before 2.7.26 and 3.x before 3.6.2, Facter 1.6.x and 2.x
before 2.0.2, Hiera before 1.3.4, and Mcollective before 2.5.2, when
running with Ruby 1.9.1 or earlier, allows local users to gain
privileges via a Trojan horse file in the current working directory,
as demonstrated using (1) rubygems/defaults/operating_system.rb, (2)
Win32API.rb, (3) Win32API.so, (4) safe_yaml.rb, (5) safe_yaml/deep.rb,
or (6) safe_yaml/deep.so; or (7) operatingsystem.rb, (8)
operatingsystem.so, (9) osfamily.rb, or (10) osfamily.so in
puppet/confine."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-456.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update facter' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:facter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/10");
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
if (rpm_check(release:"ALA", reference:"facter-1.6.18-7.25.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "facter");
}
