#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-42.
#

include("compat.inc");

if (description)
{
  script_id(69649);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2009-3743", "CVE-2010-2055", "CVE-2010-4054", "CVE-2010-4820");
  script_xref(name:"ALAS", value:"2012-42");
  script_xref(name:"RHSA", value:"2012:0095");

  script_name(english:"Amazon Linux AMI : ghostscript (ALAS-2012-42)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer overflow flaw was found in Ghostscript's TrueType bytecode
interpreter. An attacker could create a specially crafted PostScript
or PDF file that, when interpreted, could cause Ghostscript to crash
or, potentially, execute arbitrary code. (CVE-2009-3743)

It was found that Ghostscript always tried to read Ghostscript system
initialization files from the current working directory before
checking other directories, even if a search path that did not contain
the current working directory was specified with the '-I' option, or
the '-P-' option was used (to prevent the current working directory
being searched first). If a user ran Ghostscript in an
attacker-controlled directory containing a system initialization file,
it could cause Ghostscript to execute arbitrary PostScript code.
(CVE-2010-2055)

Ghostscript included the current working directory in its library
search path by default. If a user ran Ghostscript without the '-P-'
option in an attacker-controlled directory containing a specially
crafted PostScript library file, it could cause Ghostscript to execute
arbitrary PostScript code. With this update, Ghostscript no longer
searches the current working directory for library files by default.
(CVE-2010-4820)

Note: The fix for CVE-2010-4820 could possibly break existing
configurations. To use the previous, vulnerable behavior, run
Ghostscript with the '-P' option (to always search the current working
directory first).

A flaw was found in the way Ghostscript interpreted PostScript Type 1
and PostScript Type 2 font files. An attacker could create a specially
crafted PostScript Type 1 or PostScript Type 2 font file that, when
interpreted, could cause Ghostscript to crash or, potentially, execute
arbitrary code. (CVE-2010-4054)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-42.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ghostscript' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/08");
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
if (rpm_check(release:"ALA", reference:"ghostscript-8.70-11.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ghostscript-debuginfo-8.70-11.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ghostscript-devel-8.70-11.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ghostscript-doc-8.70-11.20.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-debuginfo / ghostscript-devel / etc");
}
