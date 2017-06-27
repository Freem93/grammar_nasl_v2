#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-89.
#

include("compat.inc");

if (description)
{
  script_id(69696);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2012-0876", "CVE-2012-1148");
  script_xref(name:"ALAS", value:"2012-89");
  script_xref(name:"RHSA", value:"2012:0731");

  script_name(english:"Amazon Linux AMI : expat (ALAS-2012-89)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A denial of service flaw was found in the implementation of hash
arrays in Expat. An attacker could use this flaw to make an
application using Expat consume an excessive amount of CPU time by
providing a specially crafted XML file that triggers multiple hash
function collisions. To mitigate this issue, randomization has been
added to the hash function to reduce the chance of an attacker
successfully causing intentional collisions. (CVE-2012-0876)

A memory leak flaw was found in Expat. If an XML file processed by an
application linked against Expat triggered a memory re-allocation
failure, Expat failed to free the previously allocated memory. This
could cause the application to exit unexpectedly or crash when all
available memory is exhausted. (CVE-2012-1148)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-89.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update expat' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:expat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:expat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:expat-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/19");
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
if (rpm_check(release:"ALA", reference:"expat-2.0.1-11.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"expat-debuginfo-2.0.1-11.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"expat-devel-2.0.1-11.9.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "expat / expat-debuginfo / expat-devel");
}
