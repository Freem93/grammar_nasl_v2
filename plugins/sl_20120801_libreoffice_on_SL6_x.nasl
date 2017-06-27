#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61409);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2012-2665");

  script_name(english:"Scientific Linux Security Update : libreoffice on SL6.x i386/x86_64");
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
"LibreOffice is an open source, community-developed office productivity
suite. It includes the key desktop applications, such as a word
processor, spreadsheet application, presentation manager, formula
editor, and a drawing program.

Multiple heap-based buffer overflow flaws were found in the way
LibreOffice processed encryption information in the manifest files of
OpenDocument Format files. An attacker could provide a specially
crafted OpenDocument Format file that, when opened in a LibreOffice
application, would cause the application to crash or, potentially,
execute arbitrary code with the privileges of the user running the
application. (CVE-2012-2665)

All LibreOffice users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
All running instances of LibreOffice applications must be restarted
for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1208&L=scientific-linux-errata&T=0&P=460
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?715bb340"
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
if (rpm_check(release:"SL6", reference:"autocorr-af-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-bg-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-cs-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-da-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-de-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-en-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-es-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-eu-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-fa-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-fi-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-fr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ga-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-hr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-hu-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-it-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ja-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ko-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-lb-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-lt-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-mn-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-nl-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-pl-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-pt-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ru-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sk-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sl-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sv-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-tr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-vi-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-zh-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-base-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-bsh-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-calc-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-core-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-debuginfo-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-draw-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-emailmerge-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-gdb-debug-support-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-graphicfilter-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-headless-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-impress-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-javafilter-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-af-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ar-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-as-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-bg-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-bn-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ca-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-cs-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-cy-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-da-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-de-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-dz-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-el-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-en-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-es-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-et-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-eu-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-fi-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-fr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ga-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-gl-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-gu-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-he-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-hi-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-hr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-hu-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-it-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ja-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-kn-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ko-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-lt-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-mai-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ml-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-mr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ms-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nb-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nl-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nn-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nso-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-or-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pa-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pl-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pt-BR-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pt-PT-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ro-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ru-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sk-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sl-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ss-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-st-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sv-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ta-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-te-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-th-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-tn-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-tr-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ts-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-uk-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ur-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ve-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-xh-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-zh-Hans-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-zh-Hant-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-zu-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-math-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-ogltrans-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-opensymbol-fonts-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-pdfimport-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-presentation-minimizer-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-presenter-screen-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-pyuno-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-report-builder-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-rhino-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-sdk-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-sdk-doc-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-testtools-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-ure-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-wiki-publisher-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-writer-3.4.5.2-16.1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-xsltfilter-3.4.5.2-16.1.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
