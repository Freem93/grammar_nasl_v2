#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-436.
#

include("compat.inc");

if (description)
{
  script_id(78779);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2013-4002");
  script_xref(name:"ALAS", value:"2014-436");
  script_xref(name:"RHSA", value:"2014:1319");

  script_name(english:"Amazon Linux AMI : xerces-j2 (ALAS-2014-436)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A resource consumption issue was found in the way Xerces-J handled XML
declarations. A remote attacker could use an XML document with a
specially crafted declaration using a long pseudo-attribute name that,
when parsed by an application using Xerces-J, would cause that
application to use an excessive amount of CPU."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-436.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update xerces-j2' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xerces-j2-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xerces-j2-javadoc-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xerces-j2-javadoc-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xerces-j2-javadoc-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xerces-j2-javadoc-xni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xerces-j2-scripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/03");
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
if (rpm_check(release:"ALA", reference:"xerces-j2-2.7.1-12.7.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xerces-j2-demo-2.7.1-12.7.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xerces-j2-javadoc-apis-2.7.1-12.7.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xerces-j2-javadoc-impl-2.7.1-12.7.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xerces-j2-javadoc-other-2.7.1-12.7.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xerces-j2-javadoc-xni-2.7.1-12.7.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xerces-j2-scripts-2.7.1-12.7.19.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xerces-j2 / xerces-j2-demo / xerces-j2-javadoc-apis / etc");
}
