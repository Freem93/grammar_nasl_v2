#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-359.
#

include("compat.inc");

if (description)
{
  script_id(78302);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2014-3467", "CVE-2014-3468", "CVE-2014-3469");
  script_xref(name:"ALAS", value:"2014-359");
  script_xref(name:"RHSA", value:"2014:0596");

  script_name(english:"Amazon Linux AMI : libtasn1 (ALAS-2014-359)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the asn1_get_bit_der() function of the libtasn1
library incorrectly reported the length of ASN.1-encoded data.
Specially crafted ASN.1 input could cause an application using
libtasn1 to perform an out-of-bounds access operation, causing the
application to crash or, possibly, execute arbitrary code.
(CVE-2014-3468)

Multiple incorrect buffer boundary check issues were discovered in
libtasn1. Specially crafted ASN.1 input could cause an application
using libtasn1 to crash. (CVE-2014-3467)

Multiple NULL pointer dereference flaws were found in libtasn1's
asn1_read_value() function. Specially crafted ASN.1 input could cause
an application using libtasn1 to crash, if the application used the
aforementioned function in a certain way. (CVE-2014-3469)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-359.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libtasn1' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtasn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtasn1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtasn1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtasn1-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
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
if (rpm_check(release:"ALA", reference:"libtasn1-2.3-6.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtasn1-debuginfo-2.3-6.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtasn1-devel-2.3-6.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtasn1-tools-2.3-6.6.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtasn1 / libtasn1-debuginfo / libtasn1-devel / libtasn1-tools");
}
