#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(99352);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/15 13:47:37 $");

  script_cve_id("CVE-2017-3157");
  script_xref(name:"IAVB", value:"2017-B-0026");

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
"Security Fix(es) :

  - It was found that LibreOffice disclosed contents of a
    file specified in an embedded object's preview. An
    attacker could potentially use this flaw to expose
    details of a system running LibreOffice as an online
    service via a crafted document. (CVE-2017-3157)

Bug Fix(es) :

  - Previously, an improper resource management caused the
    LibreOffice Calc spreadsheet application to terminate
    unexpectedly after closing a dialog window with
    accessibility support enabled. The resource management
    has been improved, and the described problem no longer
    occurs.

  - Previously, when an incorrect password was entered for a
    password protected document, the document has been
    considered as valid and a fallback attempt to open it as
    plain text has been made. As a consequence, it could
    appear that the document succesfully loaded, while just
    the encrypted unreadable content was shown. A fix has
    been made to terminate import attempts after entering
    incorrect password, and now nothing is loaded when a
    wrong password is entered.

  - Previously, an improper resource management caused the
    LibreOffice Calc spreadsheet application to terminate
    unexpectedly during exit, after the Text Import dialog
    for CSV (Comma-separated Value) files closed, when
    accessibility support was enabled. The resource
    management has been improved, and the described problem
    no longer occurs."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1704&L=scientific-linux-errata&F=&S=&P=7807
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ab4477b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", reference:"autocorr-af-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-bg-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ca-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-cs-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-da-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-de-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-en-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-es-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-fa-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-fi-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-fr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ga-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-hr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-hu-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-is-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-it-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ja-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ko-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-lb-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-lt-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-mn-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-nl-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-pl-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-pt-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ro-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-ru-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-sk-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-sl-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-sr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-sv-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-tr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-vi-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"autocorr-zh-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-base-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-bsh-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-calc-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-core-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-debuginfo-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-draw-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-emailmerge-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-filters-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-gdb-debug-support-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-glade-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-graphicfilter-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-impress-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-af-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ar-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-as-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-bg-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-bn-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-br-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ca-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-cs-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-cy-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-da-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-de-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-dz-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-el-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-en-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-es-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-et-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-eu-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-fa-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-fi-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-fr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ga-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-gl-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-gu-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-he-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-hi-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-hr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-hu-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-it-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ja-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-kk-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-kn-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ko-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-lt-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-lv-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-mai-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ml-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-mr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-nb-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-nl-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-nn-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-nr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-nso-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-or-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-pa-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-pl-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-pt-BR-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-pt-PT-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ro-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ru-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-si-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-sk-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-sl-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-sr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ss-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-st-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-sv-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ta-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-te-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-th-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-tn-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-tr-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ts-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-uk-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-ve-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-xh-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hans-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hant-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-langpack-zu-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-librelogo-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-math-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-nlpsolver-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-officebean-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-ogltrans-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", reference:"libreoffice-opensymbol-fonts-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-pdfimport-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-postgresql-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-pyuno-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-rhino-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-sdk-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-sdk-doc-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-ure-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-wiki-publisher-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-writer-5.0.6.2-5.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreoffice-xsltfilter-5.0.6.2-5.el7_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
