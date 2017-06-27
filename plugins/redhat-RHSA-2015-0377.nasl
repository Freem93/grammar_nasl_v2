#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0377. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81633);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2014-0247", "CVE-2014-3575", "CVE-2014-3693");
  script_xref(name:"RHSA", value:"2015:0377");

  script_name(english:"RHEL 7 : libreoffice (RHSA-2015:0377)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libreoffice packages that fix three security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

LibreOffice is an open source, community-developed office productivity
suite. It includes key desktop applications, such as a word processor,
a spreadsheet, a presentation manager, a formula editor, and a drawing
program. LibreOffice replaces OpenOffice and provides a similar but
enhanced and extended office suite.

It was found that LibreOffice documents executed macros
unconditionally, without user approval, when these documents were
opened using LibreOffice. An attacker could use this flaw to execute
arbitrary code as the user running LibreOffice by embedding malicious
VBA scripts in the document as macros. (CVE-2014-0247)

A flaw was found in the OLE (Object Linking and Embedding) generation
in LibreOffice. An attacker could use this flaw to embed malicious OLE
code in a LibreOffice document, allowing for arbitrary code execution.
(CVE-2014-3575)

A use-after-free flaw was found in the 'Remote Control' capabilities
of the LibreOffice Impress application. An attacker could use this
flaw to remotely execute code with the permissions of the user running
LibreOffice Impress. (CVE-2014-3693)

The libreoffice packages have been upgraded to upstream version
4.2.6.3, which provides a number of bug fixes and enhancements over
the previous version. Among others :

* Improved OpenXML interoperability.

* Additional statistic functions in Calc (for interoperability with
Excel and Excel's Add-in 'Analysis ToolPak').

* Various performance improvements in Calc.

* Apple Keynote and Abiword import.

* Improved MathML export.

* New Start screen with thumbnails of recently opened documents.

* Visual clue in Slide Sorter when a slide has a transition or an
animation.

* Improvements for trend lines in charts.

* Support for BCP-47 language tags. (BZ#1119709)

All libreoffice users are advised to upgrade to these updated
packages, which correct these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0247.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3575.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3693.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.documentfoundation.org/ReleaseNotes/4.2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0377.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:autocorr-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libabw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libabw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libabw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libabw-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libabw-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcmis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcmis-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcmis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcmis-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libetonyek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libetonyek-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libetonyek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libetonyek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libetonyek-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libfreehand");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libfreehand-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libfreehand-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libfreehand-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libfreehand-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:liblangtag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:liblangtag-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:liblangtag-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:liblangtag-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:liblangtag-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmwaw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmwaw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmwaw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmwaw-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmwaw-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libodfgen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libodfgen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libodfgen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libodfgen-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-gdb-debug-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-glade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-librelogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-nlpsolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreoffice-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mdds-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0377";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", reference:"autocorr-af-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-bg-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-ca-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-cs-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-da-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-de-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-en-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-es-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-fa-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-fi-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-fr-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-ga-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-hr-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-hu-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-is-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-it-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-ja-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-ko-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-lb-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-lt-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-mn-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-nl-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-pl-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-pt-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-ro-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-ru-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-sk-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-sl-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-sr-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-sv-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-tr-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-vi-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"autocorr-zh-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libabw-0.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libabw-0.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libabw-debuginfo-0.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libabw-debuginfo-0.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libabw-devel-0.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libabw-devel-0.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libabw-doc-0.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libabw-tools-0.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libcmis-0.4.1-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcmis-0.4.1-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libcmis-debuginfo-0.4.1-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcmis-debuginfo-0.4.1-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libcmis-devel-0.4.1-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcmis-devel-0.4.1-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcmis-tools-0.4.1-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libetonyek-0.0.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libetonyek-0.0.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libetonyek-debuginfo-0.0.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libetonyek-debuginfo-0.0.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libetonyek-devel-0.0.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libetonyek-devel-0.0.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libetonyek-doc-0.0.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libetonyek-tools-0.0.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libfreehand-0.0.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libfreehand-0.0.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libfreehand-debuginfo-0.0.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libfreehand-debuginfo-0.0.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libfreehand-devel-0.0.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libfreehand-devel-0.0.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libfreehand-doc-0.0.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libfreehand-tools-0.0.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"liblangtag-0.5.4-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"liblangtag-0.5.4-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"liblangtag-debuginfo-0.5.4-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"liblangtag-debuginfo-0.5.4-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"liblangtag-devel-0.5.4-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"liblangtag-devel-0.5.4-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"liblangtag-doc-0.5.4-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"liblangtag-gobject-0.5.4-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"liblangtag-gobject-0.5.4-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libmwaw-0.2.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libmwaw-0.2.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libmwaw-debuginfo-0.2.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libmwaw-debuginfo-0.2.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libmwaw-devel-0.2.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libmwaw-devel-0.2.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libmwaw-doc-0.2.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libmwaw-tools-0.2.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libodfgen-0.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libodfgen-0.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libodfgen-debuginfo-0.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libodfgen-debuginfo-0.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libodfgen-devel-0.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libodfgen-devel-0.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libodfgen-doc-0.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-base-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-bsh-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-calc-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-core-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-debuginfo-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-draw-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-emailmerge-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-filters-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-gdb-debug-support-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-glade-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-graphicfilter-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-headless-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-impress-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-af-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ar-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-as-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-bg-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-bn-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-br-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ca-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-cs-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-cy-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-da-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-de-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-dz-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-el-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-en-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-es-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-et-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-eu-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-fa-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-fi-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-fr-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ga-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-gl-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-gu-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-he-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-hi-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-hr-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-hu-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-it-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ja-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-kk-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-kn-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ko-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-lt-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-lv-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-mai-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ml-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-mr-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-nb-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-nl-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-nn-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-nr-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-nso-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-or-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-pa-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-pl-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-pt-BR-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-pt-PT-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ro-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ru-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-si-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-sk-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-sl-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-sr-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ss-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-st-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-sv-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ta-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-te-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-th-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-tn-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-tr-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ts-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-uk-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-ve-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-xh-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hans-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-zh-Hant-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-langpack-zu-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-librelogo-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-math-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-nlpsolver-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-ogltrans-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libreoffice-opensymbol-fonts-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-pdfimport-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-postgresql-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-pyuno-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-rhino-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-sdk-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-sdk-doc-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-ure-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-wiki-publisher-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-writer-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreoffice-xsltfilter-4.2.6.3-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"mdds-devel-0.10.3-1.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "autocorr-af / autocorr-bg / autocorr-ca / autocorr-cs / autocorr-da / etc");
  }
}
