#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-69.
#

include("compat.inc");

if (description)
{
  script_id(69676);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2012-1152");
  script_xref(name:"ALAS", value:"2012-69");

  script_name(english:"Amazon Linux AMI : perl-YAML-LibYAML (ALAS-2012-69)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple format string vulnerabilities in the error reporting
functionality in the YAML::LibYAML (aka YAML-LibYAML and
perl-YAML-LibYAML) module 0.38 for Perl allow remote attackers to
cause a denial of service (process crash) via format string specifiers
in a (1) YAML stream to the Load function, (2) YAML node to the
load_node function, (3) YAML mapping to the load_mapping function, or
(4) YAML sequence to the load_sequence function."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-69.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update perl-YAML-LibYAML' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-YAML-LibYAML");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-YAML-LibYAML-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/30");
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
if (rpm_check(release:"ALA", reference:"perl-YAML-LibYAML-0.38-2.2.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-YAML-LibYAML-debuginfo-0.38-2.2.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-YAML-LibYAML / perl-YAML-LibYAML-debuginfo");
}
