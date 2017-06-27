#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(95844);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/15 14:46:41 $");

  script_cve_id("CVE-2016-0794", "CVE-2016-0795");

  script_name(english:"Scientific Linux Security Update : libreoffice on SL7.x x86_64");
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
"The following packages have been upgraded to a newer upstream version:
libreoffice (5.0.6.2).

Security Fix(es) :

  - Multiple flaws were found in the Lotus Word Pro (LWP)
    document format parser in LibreOffice. By tricking a
    user into opening a specially crafted LWP document, an
    attacker could possibly use this flaw to execute
    arbitrary code with the privileges of the user opening
    the file. (CVE-2016-0794, CVE-2016-0795)

Additional Changes :"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=7832
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc868d42"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", reference:"autocorr-af-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-bg-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ca-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-cs-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-da-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-de-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-en-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-es-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-fa-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-fi-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-fr-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ga-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-hr-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-hu-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-is-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-it-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ja-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ko-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-lb-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-lt-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-mn-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-nl-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-pl-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-pt-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ro-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ru-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-sk-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-sl-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-sr-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-sv-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-tr-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-vi-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-zh-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcmis-0.5.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcmis-debuginfo-0.5.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcmis-devel-0.5.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcmis-tools-0.5.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libpagemaker-0.0.3-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libpagemaker-debuginfo-0.0.3-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libpagemaker-devel-0.0.3-1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libpagemaker-doc-0.0.3-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libpagemaker-tools-0.0.3-1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-base-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-bsh-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-calc-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-core-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-debuginfo-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-draw-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-emailmerge-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-filters-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-gdb-debug-support-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-glade-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-graphicfilter-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-impress-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-af-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ar-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-as-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-bg-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-bn-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-br-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ca-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-cs-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-cy-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-da-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-de-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-dz-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-el-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-en-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-es-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-et-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-eu-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-fa-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-fi-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-fr-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ga-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-gl-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-gu-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-he-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-hi-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-hr-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-hu-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-it-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ja-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-kk-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-kn-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ko-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-lt-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-lv-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-mai-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ml-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-mr-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-nb-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-nl-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-nn-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-nr-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-nso-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-or-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-pa-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-pl-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-pt-BR-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-pt-PT-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ro-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ru-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-si-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-sk-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-sl-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-sr-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ss-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-st-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-sv-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ta-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-te-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-th-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-tn-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-tr-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ts-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-uk-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ve-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-xh-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hans-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hant-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-zu-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-librelogo-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-math-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-nlpsolver-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-officebean-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-ogltrans-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"libreoffice-opensymbol-fonts-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-pdfimport-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-postgresql-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-pyuno-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-rhino-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-sdk-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-sdk-doc-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-ure-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-wiki-publisher-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-writer-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-xsltfilter-5.0.6.2-3.el7")) flag++;
if (rpm_check(release:"SL7", reference:"mdds-devel-0.12.1-1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
