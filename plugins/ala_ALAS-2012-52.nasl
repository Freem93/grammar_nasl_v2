#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-52.
#

include("compat.inc");

if (description)
{
  script_id(69659);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2012-0841");
  script_xref(name:"ALAS", value:"2012-52");
  script_xref(name:"RHSA", value:"2012:0324");

  script_name(english:"Amazon Linux AMI : libxml2 (ALAS-2012-52)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the hashing routine used by libxml2 arrays was
susceptible to predictable hash collisions. Sending a specially
crafted message to an XML service could result in longer processing
time, which could lead to a denial of service. To mitigate this issue,
randomization has been added to the hashing function to reduce the
chance of an attacker successfully causing intentional collisions.
(CVE-2012-0841)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-52.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libxml2' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/04");
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
if (rpm_check(release:"ALA", reference:"libxml2-2.7.6-4.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-debuginfo-2.7.6-4.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-devel-2.7.6-4.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-python-2.7.6-4.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-static-2.7.6-4.12.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-debuginfo / libxml2-devel / libxml2-python / etc");
}
