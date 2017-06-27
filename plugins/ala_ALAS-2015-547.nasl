#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-547.
#

include("compat.inc");

if (description)
{
  script_id(84248);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/06/25 13:16:45 $");

  script_cve_id("CVE-2015-3900", "CVE-2015-4020");
  script_xref(name:"ALAS", value:"2015-547");

  script_name(english:"Amazon Linux AMI : ruby20 (ALAS-2015-547)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"RubyGems provides the ability of a domain to direct clients to a
separate host that is used to fetch gems and make API calls against.
This mechanism is implemented via DNS, specificly a SRV record
_rubygems._tcp under the original requested domain. RubyGems did not
validate the hostname returned in the SRV record before sending
requests to it. (CVE-2015-3900)

As discussed upstream, CVE-2015-4020 is due to an incomplete fix for
CVE-2015-3900 , which allowed redirection to an arbitrary gem server
in any security domain."
  );
  # https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2015-009/?fid=6478
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3dfa3e8c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-547.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ruby20' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem20-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem20-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem20-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems20-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/18");
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
if (rpm_check(release:"ALA", reference:"ruby20-2.0.0.645-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-debuginfo-2.0.0.645-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-devel-2.0.0.645-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-doc-2.0.0.645-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-irb-2.0.0.645-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-libs-2.0.0.645-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem20-bigdecimal-1.2.0-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem20-io-console-0.4.2-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem20-psych-2.0.0-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems20-2.0.14-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems20-devel-2.0.14-1.27.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby20 / ruby20-debuginfo / ruby20-devel / ruby20-doc / ruby20-irb / etc");
}
