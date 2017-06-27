#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-597.
#

include("compat.inc");

if (description)
{
  script_id(86075);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/23 14:26:24 $");

  script_cve_id("CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804");
  script_xref(name:"ALAS", value:"2015-597");
  script_xref(name:"RHSA", value:"2015:1708");

  script_name(english:"Amazon Linux AMI : libXfont (ALAS-2015-597)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer overflow flaw was found in the way libXfont processed
certain Glyph Bitmap Distribution Format (BDF) fonts. A malicious,
local user could use this flaw to crash the X.Org server or,
potentially, execute arbitrary code with the privileges of the X.Org
server. (CVE-2015-1802)

An integer truncation flaw was discovered in the way libXfont
processed certain Glyph Bitmap Distribution Format (BDF) fonts. A
malicious, local user could use this flaw to crash the X.Org server
or, potentially, execute arbitrary code with the privileges of the
X.Org server. (CVE-2015-1804)

A NULL pointer dereference flaw was discovered in the way libXfont
processed certain Glyph Bitmap Distribution Format (BDF) fonts. A
malicious, local user could use this flaw to crash the X.Org server.
(CVE-2015-1803)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-597.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libXfont' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXfont-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/23");
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
if (rpm_check(release:"ALA", reference:"libXfont-1.4.5-5.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXfont-debuginfo-1.4.5-5.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libXfont-devel-1.4.5-5.12.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libXfont / libXfont-debuginfo / libXfont-devel");
}
