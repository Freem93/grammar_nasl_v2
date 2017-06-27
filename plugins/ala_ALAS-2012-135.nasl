#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-135.
#

include("compat.inc");

if (description)
{
  script_id(69625);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2012-3864", "CVE-2012-3865", "CVE-2012-3866", "CVE-2012-3867");
  script_xref(name:"ALAS", value:"2012-135");

  script_name(english:"Amazon Linux AMI : puppet (ALAS-2012-135)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Directory traversal vulnerability in lib/puppet/reports/store.rb in
Puppet before 2.6.17 and 2.7.x before 2.7.18, and Puppet Enterprise
before 2.5.2, when Delete is enabled in auth.conf, allows remote
authenticated users to delete arbitrary files on the puppet master
server via a .. (dot dot) in a node name.

Puppet before 2.6.17 and 2.7.x before 2.7.18, and Puppet Enterprise
before 2.5.2, allows remote authenticated users to read arbitrary
files on the puppet master server by leveraging an arbitrary user's
certificate and private key in a GET request.

lib/puppet/ssl/certificate_authority.rb in Puppet before 2.6.17 and
2.7.x before 2.7.18, and Puppet Enterprise before 2.5.2, does not
properly restrict the characters in the Common Name field of a
Certificate Signing Request (CSR), which makes it easier for
user-assisted remote attackers to trick administrators into signing a
crafted agent certificate via ANSI control sequences.

lib/puppet/defaults.rb in Puppet 2.7.x before 2.7.18, and Puppet
Enterprise before 2.5.2, uses 0644 permissions for
last_run_report.yaml, which allows local users to obtain sensitive
configuration information by leveraging access to the puppet master
server to read this file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-135.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update puppet' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:puppet-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:puppet-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/15");
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
if (rpm_check(release:"ALA", reference:"puppet-2.7.18-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"puppet-debuginfo-2.7.18-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"puppet-server-2.7.18-1.9.amzn1")) flag++;

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
