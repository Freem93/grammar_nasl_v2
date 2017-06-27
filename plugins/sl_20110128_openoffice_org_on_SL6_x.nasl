#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60947);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453", "CVE-2010-3454", "CVE-2010-3689", "CVE-2010-4253", "CVE-2010-4643");

  script_name(english:"Scientific Linux Security Update : openoffice.org on SL6.x i386/x86_64");
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
"An array index error and an integer signedness error were found in the
way OpenOffice.org parsed certain Rich Text Format (RTF) files. An
attacker could use these flaws to create a specially crafted RTF file
that, when opened, would cause OpenOffice.org to crash or, possibly,
execute arbitrary code with the privileges of the user running
OpenOffice.org. (CVE-2010-3451, CVE-2010-3452)

A heap-based buffer overflow flaw and an array index error were found
in the way OpenOffice.org parsed certain Microsoft Office Word
documents. An attacker could use these flaws to create a specially
crafted Microsoft Office Word document that, when opened, would cause
OpenOffice.org to crash or, possibly, execute arbitrary code with the
privileges of the user running OpenOffice.org. (CVE-2010-3453,
CVE-2010-3454)

A heap-based buffer overflow flaw was found in the way OpenOffice.org
parsed certain Microsoft Office PowerPoint files. An attacker could
use this flaw to create a specially crafted Microsoft Office
PowerPoint file that, when opened, would cause OpenOffice.org to crash
or, possibly, execute arbitrary code with the privileges of the user
running OpenOffice.org. (CVE-2010-4253)

A heap-based buffer overflow flaw was found in the way OpenOffice.org
parsed certain TARGA (Truevision TGA) files. An attacker could use
this flaw to create a specially crafted TARGA file. If a document
containing this specially crafted TARGA file was opened, or if a user
tried to insert the file into an existing document, it would cause
OpenOffice.org to crash or, possibly, execute arbitrary code with the
privileges of the user running OpenOffice.org. (CVE-2010-4643)

A directory traversal flaw was found in the way OpenOffice.org handled
the installation of XSLT filter descriptions packaged in Java Archive
(JAR) files, as well as the installation of OpenOffice.org Extension
(.oxt) files. An attacker could use these flaws to create a specially
crafted XSLT filter description or extension file that, when opened,
would cause the OpenOffice.org Extension Manager to modify files
accessible to the user installing the JAR or extension file.
(CVE-2010-3450)

A flaw was found in the script that launches OpenOffice.org. In some
situations, a '.' character could be included in the LD_LIBRARY_PATH
variable, allowing a local attacker to execute arbitrary code with the
privileges of the user running OpenOffice.org, if that user ran
OpenOffice.org from within an attacker-controlled directory.
(CVE-2010-3689)

This update also fixes the following bug :

  - OpenOffice.org did not create a lock file when opening a
    file that was on a share mounted via SFTP. Additionally,
    if there was a lock file, it was ignored. This could
    result in data loss if a file in this situation was
    opened simultaneously by another user. (BZ#671087)

All running instances of OpenOffice.org applications must be restarted
for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=5286
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5819c8e0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=671087"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/28");
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
if (rpm_check(release:"SL6", reference:"autocorr-af-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-bg-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-cs-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-da-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-de-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-en-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-es-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-eu-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-fa-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-fi-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-fr-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ga-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-hu-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-it-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ja-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ko-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-lb-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-lt-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-mn-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-nl-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-pl-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-pt-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ru-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sk-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sl-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sv-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-tr-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-vi-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-zh-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"broffice.org-base-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"broffice.org-brand-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"broffice.org-calc-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"broffice.org-draw-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"broffice.org-impress-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"broffice.org-math-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"broffice.org-writer-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-base-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-base-core-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-brand-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-bsh-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-calc-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-calc-core-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-core-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-devel-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-draw-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-draw-core-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-emailmerge-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-graphicfilter-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-headless-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-impress-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-impress-core-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-javafilter-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-af_ZA-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-ar-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-as_IN-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-bg_BG-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-bn-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-ca_ES-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-cs_CZ-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-cy_GB-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-da_DK-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-de-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-dz-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-el_GR-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-en-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-es-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-et_EE-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-eu_ES-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-fi_FI-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-fr-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-ga_IE-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-gl_ES-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-gu_IN-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-he_IL-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-hi_IN-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-hr_HR-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-hu_HU-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-it-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-ja_JP-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-kn_IN-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-ko_KR-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-lt_LT-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-mai_IN-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-ml_IN-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-mr_IN-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-ms_MY-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-nb_NO-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-nl-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-nn_NO-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-nr_ZA-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-nso_ZA-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-or_IN-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-pa-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-pl_PL-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-pt_BR-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-pt_PT-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-ro-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-ru-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-sk_SK-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-sl_SI-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-sr-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-ss_ZA-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-st_ZA-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-sv-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-ta_IN-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-te_IN-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-th_TH-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-tn_ZA-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-tr_TR-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-ts_ZA-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-uk-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-ur-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-ve_ZA-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-xh_ZA-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-zh_CN-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-zh_TW-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-langpack-zu_ZA-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-math-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-math-core-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-ogltrans-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-opensymbol-fonts-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-pdfimport-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-presentation-minimizer-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-presenter-screen-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-pyuno-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-report-builder-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-rhino-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-sdk-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-sdk-doc-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-testtools-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-ure-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-wiki-publisher-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-writer-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-writer-core-3.2.1-19.6.el6_0.5")) flag++;
if (rpm_check(release:"SL6", reference:"openoffice.org-xsltfilter-3.2.1-19.6.el6_0.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
