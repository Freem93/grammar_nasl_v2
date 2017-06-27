#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-618.
#

include("compat.inc");

if (description)
{
  script_id(87344);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2015-7501");
  script_xref(name:"ALAS", value:"2015-618");

  script_name(english:"Amazon Linux AMI : apache-commons-collections (ALAS-2015-618)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the Apache commons-collections library permitted
code execution when deserializing objects involving a specially
constructed chain of classes. A remote attacker could use this flaw to
execute arbitrary code with the permissions of the application using
the commons-collections library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-618.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update apache-commons-collections' to update your system."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:apache-commons-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:apache-commons-collections-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:apache-commons-collections-testframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:apache-commons-collections-testframework-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"apache-commons-collections-3.2.1-11.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"apache-commons-collections-javadoc-3.2.1-11.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"apache-commons-collections-testframework-3.2.1-11.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"apache-commons-collections-testframework-javadoc-3.2.1-11.9.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache-commons-collections / apache-commons-collections-javadoc / etc");
}
