#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(99505);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/21 16:53:28 $");

  script_cve_id("CVE-2017-3157");
  script_xref(name:"IAVB", value:"2017-B-0026");

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
"Security Fix(es) :

  - It was found that LibreOffice disclosed contents of a
    file specified in an embedded object's preview. An
    attacker could potentially use this flaw to expose
    details of a system running LibreOffice as an online
    service via a crafted document. (CVE-2017-3157)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1704&L=scientific-linux-errata&F=&S=&P=17275
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?974fb6f0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");
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
if (rpm_check(release:"SL6", reference:"autocorr-af-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-bg-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ca-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-cs-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-da-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-de-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-en-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-es-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-fa-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-fi-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-fr-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ga-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-hr-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-hu-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-is-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-it-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ja-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ko-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-lb-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-lt-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-mn-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-nl-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-pl-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-pt-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ro-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ru-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sk-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sl-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sr-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sv-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-tr-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-vi-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-zh-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-base-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-bsh-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-calc-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-core-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-debuginfo-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-draw-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-emailmerge-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-filters-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-gdb-debug-support-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-glade-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-graphicfilter-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-headless-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-impress-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-af-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ar-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-as-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-bg-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-bn-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ca-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-cs-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-cy-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-da-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-de-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-dz-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-el-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-en-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-es-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-et-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-eu-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-fi-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-fr-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ga-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-gl-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-gu-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-he-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-hi-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-hr-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-hu-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-it-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ja-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-kn-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ko-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-lt-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-mai-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ml-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-mr-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ms-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nb-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nl-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nn-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nr-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nso-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-or-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pa-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pl-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pt-BR-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pt-PT-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ro-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ru-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sk-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sl-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sr-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ss-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-st-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sv-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ta-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-te-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-th-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-tn-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-tr-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ts-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-uk-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ur-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ve-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-xh-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-zh-Hans-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-zh-Hant-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-zu-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-librelogo-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-math-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-nlpsolver-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-officebean-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-ogltrans-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-opensymbol-fonts-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-pdfimport-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-pyuno-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-rhino-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-sdk-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-sdk-doc-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-ure-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-wiki-publisher-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-writer-4.3.7.2-2.el6_9.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-xsltfilter-4.3.7.2-2.el6_9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
