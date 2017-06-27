#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61410);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2012-2665");

  script_name(english:"Scientific Linux Security Update : openoffice.org on SL5.x i386/x86_64");
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
"OpenOffice.org is an office productivity suite that includes desktop
applications, such as a word processor, spreadsheet application,
presentation manager, formula editor, and a drawing program.

Multiple heap-based buffer overflow flaws were found in the way
OpenOffice.org processed encryption information in the manifest files
of OpenDocument Format files. An attacker could provide a specially
crafted OpenDocument Format file that, when opened in an
OpenOffice.org application, would cause the application to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2012-2665)

All OpenOffice.org users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
All running instances of OpenOffice.org applications must be restarted
for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1208&L=scientific-linux-errata&T=0&P=595
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5236ef1e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/03");
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
if (rpm_check(release:"SL5", reference:"openoffice.org-base-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-calc-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-core-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-debuginfo-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-draw-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-emailmerge-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-graphicfilter-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-headless-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-impress-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-javafilter-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-af_ZA-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ar-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-as_IN-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-bg_BG-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-bn-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ca_ES-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-cs_CZ-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-cy_GB-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-da_DK-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-de-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-el_GR-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-es-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-et_EE-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-eu_ES-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-fi_FI-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-fr-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ga_IE-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-gl_ES-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-gu_IN-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-he_IL-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-hi_IN-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-hr_HR-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-hu_HU-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-it-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ja_JP-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-kn_IN-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ko_KR-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-lt_LT-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ml_IN-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-mr_IN-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ms_MY-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nb_NO-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nl-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nn_NO-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nr_ZA-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nso_ZA-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-or_IN-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pa_IN-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pl_PL-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pt_BR-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pt_PT-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ru-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sk_SK-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sl_SI-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sr_CS-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ss_ZA-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-st_ZA-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sv-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ta_IN-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-te_IN-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-th_TH-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-tn_ZA-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-tr_TR-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ts_ZA-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ur-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ve_ZA-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-xh_ZA-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-zh_CN-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-zh_TW-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-zu_ZA-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-math-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-pyuno-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-sdk-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-sdk-doc-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-testtools-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-ure-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-writer-3.1.1-19.10.el5_8.4")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-xsltfilter-3.1.1-19.10.el5_8.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
