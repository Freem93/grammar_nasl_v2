#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60661);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-0200", "CVE-2009-0201");

  script_name(english:"Scientific Linux Security Update : openoffice.org on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"CVE-2009-0200 OpenOffice.org Word document Integer Underflow

CVE-2009-0201 OpenOffice.org Word document buffer overflow

An integer underflow flaw and a boundary error flaw, both possibly
leading to a heap-based buffer overflow, were found in the way
OpenOffice.org parses certain records in Microsoft Word documents. An
attacker could create a specially crafted Microsoft Word document,
which once opened by an unsuspecting user, could cause OpenOffice.org
to crash or, potentially, execute arbitrary code with the permissions
of the user running OpenOffice.org. (CVE-2009-0200, CVE-2009-0201)

Allrunning instances of OpenOffice.org applications must be restarted
for this update to take effect.

Note: The openoffice.org2 update for SL4 has been delayed."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0909&L=scientific-linux-errata&T=0&P=467
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7a593db"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"openoffice.org-1.1.2-44.2.0.EL3")) flag++;
if (rpm_check(release:"SL3", reference:"openoffice.org-i18n-1.1.2-44.2.0.EL3")) flag++;
if (rpm_check(release:"SL3", reference:"openoffice.org-libs-1.1.2-44.2.0.EL3")) flag++;

if (rpm_check(release:"SL4", reference:"openoffice.org-1.1.5-10.6.0.7.EL4.1")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org-i18n-1.1.5-10.6.0.7.EL4.1")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org-kde-1.1.5-10.6.0.7.EL4.1")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org-libs-1.1.5-10.6.0.7.EL4.1")) flag++;

if (rpm_check(release:"SL5", reference:"openoffice.org-base-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-calc-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-core-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-draw-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-emailmerge-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-graphicfilter-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-headless-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-impress-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-javafilter-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-af_ZA-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ar-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-as_IN-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-bg_BG-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-bn-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ca_ES-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-cs_CZ-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-cy_GB-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-da_DK-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-de-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-el_GR-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-es-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-et_EE-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-eu_ES-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-fi_FI-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-fr-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ga_IE-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-gl_ES-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-gu_IN-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-he_IL-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-hi_IN-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-hr_HR-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-hu_HU-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-it-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ja_JP-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-kn_IN-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ko_KR-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-lt_LT-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ml_IN-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-mr_IN-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ms_MY-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nb_NO-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nl-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nn_NO-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nr_ZA-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nso_ZA-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-or_IN-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pa_IN-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pl_PL-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pt_BR-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pt_PT-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ru-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sk_SK-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sl_SI-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sr_CS-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ss_ZA-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-st_ZA-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sv-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ta_IN-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-te_IN-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-th_TH-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-tn_ZA-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-tr_TR-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ts_ZA-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ur-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ve_ZA-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-xh_ZA-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-zh_CN-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-zh_TW-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-zu_ZA-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-math-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-pyuno-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-sdk-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-sdk-doc-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-testtools-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-writer-2.3.0-6.11.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-xsltfilter-2.3.0-6.11.el5_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
