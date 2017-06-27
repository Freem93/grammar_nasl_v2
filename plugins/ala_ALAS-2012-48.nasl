#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-48.
#

include("compat.inc");

if (description)
{
  script_id(69655);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2010-2642", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554");
  script_xref(name:"ALAS", value:"2012-48");
  script_xref(name:"RHSA", value:"2012:0137");

  script_name(english:"Amazon Linux AMI : texlive (ALAS-2012-48)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"TeX Live embeds a copy of t1lib. The t1lib library allows you to
rasterize bitmaps from PostScript Type 1 fonts. The following issues
affect t1lib code :

Two heap-based buffer overflow flaws were found in the way t1lib
processed Adobe Font Metrics (AFM) files. If a specially crafted font
file was opened by a TeX Live utility, it could cause the utility to
crash or, potentially, execute arbitrary code with the privileges of
the user running the utility. (CVE-2010-2642 , CVE-2011-0433)

An invalid pointer dereference flaw was found in t1lib. A specially
crafted font file could, when opened, cause a TeX Live utility to
crash or, potentially, execute arbitrary code with the privileges of
the user running the utility. (CVE-2011-0764)

A use-after-free flaw was found in t1lib. A specially crafted font
file could, when opened, cause a TeX Live utility to crash or,
potentially, execute arbitrary code with the privileges of the user
running the utility. (CVE-2011-1553)

An off-by-one flaw was found in t1lib. A specially crafted font file
could, when opened, cause a TeX Live utility to crash or, potentially,
execute arbitrary code with the privileges of the user running the
utility. (CVE-2011-1554)

An out-of-bounds memory read flaw was found in t1lib. A specially
crafted font file could, when opened, cause a TeX Live utility to
crash. (CVE-2011-1552)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-48.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update texlive' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kpathsea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kpathsea-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mendexk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-dviutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-east-asian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xetex");
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
if (rpm_check(release:"ALA", reference:"kpathsea-2007-57.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kpathsea-devel-2007-57.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mendexk-2.6e-57.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"texlive-2007-57.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"texlive-afm-2007-57.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"texlive-context-2007-57.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"texlive-debuginfo-2007-57.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"texlive-dvips-2007-57.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"texlive-dviutils-2007-57.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"texlive-east-asian-2007-57.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"texlive-latex-2007-57.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"texlive-utils-2007-57.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"texlive-xetex-2007-57.9.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kpathsea / kpathsea-devel / mendexk / texlive / texlive-afm / etc");
}
