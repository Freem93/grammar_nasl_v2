#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60798);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-0395");

  script_name(english:"Scientific Linux Security Update : openoffice.org2 on SL4.x i386/x86_64");
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
"A flaw was found in the way OpenOffice.org enforced a macro security
setting for macros, written in the Python scripting language, that
were embedded in OpenOffice.org documents. If a user were tricked into
opening a specially crafted OpenOffice.org document and previewed the
macro directory structure, it could lead to Python macro execution
even if macro execution was disabled. (CVE-2010-0395)

All running instances of OpenOffice.org applications must be restarted
for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1006&L=scientific-linux-errata&T=0&P=775
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?720d61c7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/07");
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
if (rpm_check(release:"SL4", reference:"gnome-themes-2.8.0-2")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-base-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-calc-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-core-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-draw-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"openoffice.org2-emailmerge-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-graphicfilter-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-impress-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-javafilter-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-af_ZA-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-ar-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-bg_BG-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-bn-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-ca_ES-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-cs_CZ-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-cy_GB-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-da_DK-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-de-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-el_GR-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-es-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-et_EE-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-eu_ES-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-fi_FI-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-fr-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-ga_IE-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-gl_ES-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-gu_IN-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-he_IL-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-hi_IN-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-hr_HR-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-hu_HU-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-it-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-ja_JP-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-ko_KR-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-lt_LT-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-ms_MY-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-nb_NO-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-nl-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-nn_NO-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-pa_IN-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-pl_PL-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-pt_BR-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-pt_PT-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-ru-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-sk_SK-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-sl_SI-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-sr_CS-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-sv-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-ta_IN-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-th_TH-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-tr_TR-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-zh_CN-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-zh_TW-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-langpack-zu_ZA-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-math-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"openoffice.org2-pyuno-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-testtools-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-writer-2.0.4-5.7.0.6.1.4")) flag++;
if (rpm_check(release:"SL4", reference:"openoffice.org2-xsltfilter-2.0.4-5.7.0.6.1.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
