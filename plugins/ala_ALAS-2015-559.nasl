#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-559.
#

include("compat.inc");

if (description)
{
  script_id(84595);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/07/08 13:34:44 $");

  script_cve_id("CVE-2014-9679", "CVE-2015-1158", "CVE-2015-1159");
  script_xref(name:"ALAS", value:"2015-559");
  script_xref(name:"RHSA", value:"2015:1123");

  script_name(english:"Amazon Linux AMI : cups (ALAS-2015-559)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A string reference count bug was found in cupsd, causing premature
freeing of string objects. An attacker can submit a malicious print
job that exploits this flaw to dismantle ACLs protecting privileged
operations, allowing a replacement configuration file to be uploaded
which in turn allows the attacker to run arbitrary code in the CUPS
server (CVE-2015-1158)

A cross-site scripting flaw was found in the cups web templating
engine. An attacker could use this flaw to bypass the default
configuration settings that bind the CUPS scheduler to the 'localhost'
or loopback interface. (CVE-2015-1159)

An integer overflow leading to a heap-based buffer overflow was found
in the way cups handled compressed raster image files. An attacker
could create a specially crafted image file, which when passed via the
cups Raster filter, could cause the cups filter to crash.
(CVE-2014-9679)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-559.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update cups' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/08");
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
if (rpm_check(release:"ALA", reference:"cups-1.4.2-67.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cups-debuginfo-1.4.2-67.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cups-devel-1.4.2-67.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cups-libs-1.4.2-67.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cups-lpd-1.4.2-67.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"cups-php-1.4.2-67.21.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-debuginfo / cups-devel / cups-libs / cups-lpd / etc");
}
