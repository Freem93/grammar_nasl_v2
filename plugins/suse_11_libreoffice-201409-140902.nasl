#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(77663);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/11/17 18:50:41 $");

  script_cve_id("CVE-2013-4156", "CVE-2014-3575");

  script_name(english:"SuSE 11.3 Security Update : LibreOffice (SAT Patch Number 9677)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LibreOffice was updated to version 4.0.3.3.26. (SUSE 4.0-patch26, tag
suse-4.0-26, based on upstream 4.0.3.3).

Two security issues have been fixed :

  - DOCM memory corruption vulnerability. (CVE-2013-4156,
    bnc#831578)

  - Data exposure using crafted OLE objects. (CVE-2014-3575,
    bnc#893141) The following non-security issues have been
    fixed :

  - chart shown flipped. (bnc#834722)

  - chart missing dataset. (bnc#839727)

  - import new line in text. (bnc#828390)

  - lines running off screens. (bnc#819614)

  - add set-all language menu. (bnc#863021)

  - text rotation. (bnc#783433, bnc#862510)

  - page border shadow testcase. (bnc#817956)

  - one more clickable field fix. (bnc#802888)

  - multilevel labels are rotated. (bnc#820273)

  - incorrect nested table margins. (bnc#816593)

  - use BitmapURL only if its valid. (bnc#821567)

  - import gradfill for text colors. (bnc#870234)

  - fix undo of paragraph attributes. (bnc#828598)

  - stop-gap solution to avoid crash. (bnc#830205)

  - import images with duotone filter. (bnc#820077)

  - missing drop downs for autofilter. (bnc#834705)

  - typos in first page style creation. (bnc#820836)

  - labels wrongly interpreted as dates. (bnc#834720)

  - RTF import of fFilled shape property. (bnc#825305)

  - placeholders text size is not correct. (bnc#831457)

  - cells value formatted with wrong output. (bnc#821795)

  - RTF import of freeform shape coordinates. (bnc#823655)

  - styles (rename &amp;) copy to different decks.
    (bnc#757432)

  - XLSX Chart import with internal data table. (bnc#819822)

  - handle M.d.yyyy date format in DOCX import. (bnc#820509)

  - paragraph style in empty first page header. (bnc#823651)

  - copying slides having same master page name.
    (bnc#753460)

  - printing handouts using the default, 'Order'.
    (bnc#835985)

  - wrap polygon was based on dest size of picture.
    (bnc#820800)

  - added common flags support for SEQ field import.
    (bnc#825976)

  - hyperlinks of illustration index in DOCX export.
    (bnc#834035)

  - allow insertion of redlines with an empty author.
    (bnc#837302)

  - handle drawinglayer rectangle inset in VML import.
    (bnc#779642)

  - don't apply complex font size to non-complex font.
    (bnc#820819)

  - issue with negative seeks in win32 shell extension.
    (bnc#829017)

  - slide appears quite garbled when imported from PPTX.
    (bnc#593612)

  - initial MCE support in writerfilter ooxml tokenizer.
    (bnc#820503)

  - MSWord uses \xb for linebreaks in DB fields, take 2.
    (bnc#878854)

  - try harder to convert floating tables to text frames.
    (bnc#779620)

  - itemstate in parent style incorrectly reported as set.
    (bnc#819865)

  - default color hidden by Default style in writerfilter.
    (bnc#820504)

  - DOCX document crashes when using internal OOXML filter.
    (bnc#382137)

  - ugly workaround for external leading with symbol fonts.
    (bnc#823626)

  - followup fix for exported xlsx causes errors for
    mso2007. (bnc#823935)

  - we only support simple labels in the
    InternalDataProvider. (bnc#864396)

  - RTF import: fix import of numbering bullet associated
    font. (bnc#823675)

  - page specific footer extended to every pages in DOCX
    export. (bnc#654230)

  - v:textbox mso-fit-shape-to-text style property in VML
    import. (bnc#820788)

  - w:spacing in a paragraph should also apply to as-char
    objects. (bnc#780044)

  - compatibility setting for MS Word wrapping text in less
    space. (bnc#822908)

  - fix SwWrtShell::SelAll() to work with empty table at doc
    start (bnc#825891)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=382137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=593612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=654230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=753460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=783433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=830205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=835985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=837302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=839727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=862510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=870234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=878854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=893141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4156.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3575.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9677.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-base-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-draw-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-en-US");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-help-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-icon-themes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-impress-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-base-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-base-drivers-postgresql-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-base-extensions-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-calc-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-calc-extensions-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-draw-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-draw-extensions-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-filters-optional-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-gnome-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-cs-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-da-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-de-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-en-GB-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-en-US-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-es-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-fr-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-gu-IN-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-hi-IN-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-hu-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-it-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-ja-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-ko-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-nl-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-pl-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-pt-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-pt-BR-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-ru-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-sv-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-zh-CN-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-help-zh-TW-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-icon-themes-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-impress-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-impress-extensions-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-kde-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-kde4-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-af-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-ar-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-ca-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-cs-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-da-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-de-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-en-GB-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-es-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-fi-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-fr-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-gu-IN-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-hi-IN-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-hu-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-it-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-ja-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-ko-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-nb-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-nl-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-nn-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-pl-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-pt-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-pt-BR-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-ru-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-sk-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-sv-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-xh-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-zh-CN-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-zh-TW-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-l10n-zu-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-mailmerge-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-math-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-mono-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-officebean-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-pyuno-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-writer-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libreoffice-writer-extensions-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-base-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-base-extensions-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-calc-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-calc-extensions-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-draw-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-draw-extensions-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-filters-optional-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-gnome-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-cs-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-da-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-de-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-en-GB-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-en-US-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-es-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-fr-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-gu-IN-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-hi-IN-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-hu-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-it-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-ja-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-ko-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-nl-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-pl-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-pt-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-pt-BR-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-ru-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-sv-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-zh-CN-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-help-zh-TW-4.0.3.3.26-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-icon-themes-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-impress-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-impress-extensions-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-kde-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-kde4-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-af-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-ar-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-ca-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-cs-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-da-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-de-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-en-GB-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-es-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-fi-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-fr-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-gu-IN-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-hi-IN-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-hu-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-it-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-ja-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-ko-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-nb-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-nl-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-nn-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-pl-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-pt-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-pt-BR-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-ru-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-sk-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-sv-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-xh-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-zh-CN-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-zh-TW-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-l10n-zu-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-mailmerge-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-math-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-mono-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-officebean-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-pyuno-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-writer-4.0.3.3.26-0.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libreoffice-writer-extensions-4.0.3.3.26-0.6.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
