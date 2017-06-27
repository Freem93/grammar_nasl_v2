#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(87400);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/16 15:10:33 $");

  script_cve_id("CVE-2015-4551", "CVE-2015-5212", "CVE-2015-5213", "CVE-2015-5214");

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
"It was discovered that LibreOffice did not properly restrict automatic
link updates. By tricking a victim into opening specially crafted
documents, an attacker could possibly use this flaw to disclose
contents of files accessible by the victim. (CVE-2015-4551)

An integer underflow flaw leading to a heap-based buffer overflow when
parsing PrinterSetup data was discovered. By tricking a user into
opening a specially crafted document, an attacker could possibly
exploit this flaw to execute arbitrary code with the privileges of the
user opening the file. (CVE-2015-5212)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way LibreOffice processed certain Microsoft Word .doc
files. By tricking a user into opening a specially crafted Microsoft
Word .doc document, an attacker could possibly use this flaw to
execute arbitrary code with the privileges of the user opening the
file. (CVE-2015-5213)

It was discovered that LibreOffice did not properly sanity check
bookmark indexes. By tricking a user into opening a specially crafted
document, an attacker could possibly use this flaw to execute
arbitrary code with the privileges of the user opening the file.
(CVE-2015-5214)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=1605
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b1b16d0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"autocorr-af-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-bg-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ca-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-cs-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-da-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-de-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-en-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-es-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-fa-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-fi-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-fr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ga-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-hr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-hu-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-is-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-it-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ja-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ko-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-lb-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-lt-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-mn-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-nl-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-pl-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-pt-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ro-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ru-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sk-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sl-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sv-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-tr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-vi-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-zh-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-base-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-bsh-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-calc-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-core-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-debuginfo-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-draw-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-emailmerge-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-filters-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-gdb-debug-support-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-glade-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-graphicfilter-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-headless-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-impress-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-af-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ar-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-as-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-bg-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-bn-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ca-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-cs-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-cy-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-da-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-de-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-dz-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-el-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-en-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-es-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-et-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-eu-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-fi-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-fr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ga-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-gl-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-gu-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-he-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-hi-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-hr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-hu-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-it-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ja-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-kn-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ko-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-lt-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-mai-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ml-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-mr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ms-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nb-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nl-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nn-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nso-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-or-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pa-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pl-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pt-BR-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pt-PT-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ro-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ru-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sk-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sl-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ss-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-st-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sv-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ta-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-te-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-th-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-tn-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-tr-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ts-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-uk-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ur-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ve-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-xh-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-zh-Hans-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-zh-Hant-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-zu-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-librelogo-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-math-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-nlpsolver-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-ogltrans-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-opensymbol-fonts-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-pdfimport-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-pyuno-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-rhino-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-sdk-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-sdk-doc-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-ure-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-wiki-publisher-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-writer-4.2.8.2-11.el6_7.1")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-xsltfilter-4.2.8.2-11.el6_7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
