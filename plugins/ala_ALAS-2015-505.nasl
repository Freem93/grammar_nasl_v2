#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-505.
#

include("compat.inc");

if (description)
{
  script_id(82833);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/04/17 13:32:19 $");

  script_cve_id("CVE-2014-8962", "CVE-2014-9028");
  script_xref(name:"ALAS", value:"2015-505");
  script_xref(name:"RHSA", value:"2015:0767");

  script_name(english:"Amazon Linux AMI : flac (ALAS-2015-505)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow flaw was found in the way flac decoded FLAC audio
files. An attacker could create a specially crafted FLAC audio file
that could cause an application using the flac library to crash or
execute arbitrary code when the file was read. (CVE-2014-9028)

A buffer over-read flaw was found in the way flac processed certain
ID3v2 metadata. An attacker could create a specially crafted FLAC
audio file that could cause an application using the flac library to
crash when the file was read. (CVE-2014-8962)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-505.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update flac' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flac-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:flac-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/17");
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
if (rpm_check(release:"ALA", reference:"flac-1.2.1-7.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"flac-debuginfo-1.2.1-7.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"flac-devel-1.2.1-7.7.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flac / flac-debuginfo / flac-devel");
}
