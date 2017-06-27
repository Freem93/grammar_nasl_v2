#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61250);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2010-2642", "CVE-2011-0433", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554");

  script_name(english:"Scientific Linux Security Update : texlive on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"TeX Live is an implementation of TeX. TeX takes a text file and a set
of formatting commands as input, and creates a typesetter-independent
DeVice Independent (DVI) file as output. The texlive packages provide
a number of utilities, including dvips.

TeX Live embeds a copy of t1lib. The t1lib library allows you to
rasterize bitmaps from PostScript Type 1 fonts. The following issues
affect t1lib code :

Two heap-based buffer overflow flaws were found in the way t1lib
processed Adobe Font Metrics (AFM) files. If a specially crafted font
file was opened by a TeX Live utility, it could cause the utility to
crash or, potentially, execute arbitrary code with the privileges of
the user running the utility. (CVE-2010-2642, CVE-2011-0433)

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
crash. (CVE-2011-1552)

All users of texlive are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=2943
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?533e946e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"kpathsea-2007-57.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"kpathsea-devel-2007-57.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"mendexk-2.6e-57.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"texlive-2007-57.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"texlive-afm-2007-57.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"texlive-context-2007-57.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"texlive-debuginfo-2007-57.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"texlive-dvips-2007-57.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"texlive-dviutils-2007-57.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"texlive-east-asian-2007-57.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"texlive-latex-2007-57.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"texlive-utils-2007-57.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"texlive-xetex-2007-57.el6_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
