#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-868.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74849);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2012-4233");

  script_name(english:"openSUSE Security Update : libreoffice (openSUSE-SU-2012:1686-1)");
  script_summary(english:"Check for the openSUSE-2012-868 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LibreOffice was updated to 3.5.4.13 (3.5.6rc2 based), fixing a
security issue and lots of bugs :

  - NULL pointer dereference (bnc#778669, CVE-2012-4233)

  - bullet-color-pptx-import.diff: bullets should have same
    color as following text by default; missing part of the
    fix (bnc#734733)

  - update to suse-3.5.4.13 (SUSE 3.5 bugfix release 13,
    based on upstream 3.5.6-rc2)

  - polygon fill rule (bnc#759172)

  - open XML in Writer (bnc#777181)

  - undo in text objects (fdo#36138)

  - broken numbering level (bnc#760019)

  - better MathML detection (bnc#774921)

  - pictures in DOCX import (bnc#772094)

  - collapsing border painting (fdo#39415)

  - better DOCX text box export (fdo#45724)

  - hidden text in PPTX import (bnc#759180)

  - slide notes in PPTX import (bnc#768027)

  - RTL paragraphs in DOC import (fdo#43398)

  - better vertical text imports (bnc#744510)

  - HYPERLINK field in DOCX import (fdo#51034)

  - shadow color on partial redraw (bnc#773515)

  - floating objects in DOCX import (bnc#775899)

  - graphite2 hyphenation regression (fdo#49486)

  - missing shape position and size (bnc#760997)

  - page style attributes in ODF import (fdo#38056)

  - browsing in Template dialog crasher (fdo#46249)

  - wrong master slide shape being used (bnc#758565)

  - page borders regression in ODT import (fdo#38056)

  - invalidate bound rect after drag&drop (fdo#44534)

  - rotated shape margins in PPTX import (bnc#773048)

  - pasting into more than 1 sheet crasher (fdo#47311)

  - crashers in PPT/PPTX import (bnc#768027, bnc#774167

  - missing footnote in DOCX/DOC/RTF export (fdo#46020)

  - checkbox no-label behaviour (fdo#51336, bnc#757602)

  - try somewhat harder to read w:position (bnc#773061)

  - FormatNumber can handle sal_uInt32 values (fdo#51793)

  - rectangle-paragraph tables in DOCX import (bnc#775899)

  - header and bullet in slideshow transition (bnc#759172)

  - default background color in DOC/DOCX export (fdo#45724)

  - font name / size attributes in DOCX import (bnc#774681)

  - zero rect. size causing wrong line positions (fdo#47434)

  - adjusted display of Bracket/BracePair in PPT
    (bnc#741480)

  - use Unicode functions for QuickStarter tooltip
    (fdo#52143)

  - TabRatio API and detect macro at group shape fixes
    (bnc#770708)

  - indented text in DOCX file does not wrap correctly
    (bnc#775906)

  - undocked toolbars do not show all icons in special ratio
    (fdo#47071)

  - cross-reference text when Caption order is Numbering
    first (fdo#50801)

  - bullet color same as following text by default
    (bnc#719988, bnc#734733)

  - misc RTF import fixes (rhbz#819304, fdo#49666,
    bnc#774681, fdo#51772, fdo#48033, fdo#52066, fdo#48335,
    fdo#48446, fdo#49892, fdo#46966)

  - update to libvisio 0.0.19 :

  - file displays as blank page in Draw (fdo#50990)

  - use the vendor SUSE instead of Novell, Inc.

  - install-with-vendor-SUSE.diff: fix installation with the
    vendor 'SUSE'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-12/msg00047.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=719988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=734733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=741480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=770708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=778669"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreoffice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-drivers-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-base-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw-extensions-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-filters-optional-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-en-US");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-en-ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-crystal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-galaxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-hicontrast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-tango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-themes-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress-extensions-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-be-BY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-en-ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pa-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-math-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-officebean-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-pyuno-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-sdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-base-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-base-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-base-drivers-mysql-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-base-drivers-mysql-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-base-drivers-postgresql-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-base-drivers-postgresql-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-base-extensions-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-branding-upstream-3.5.4.13-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-calc-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-calc-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-calc-extensions-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-debugsource-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-draw-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-draw-extensions-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-draw-extensions-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-filters-optional-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-filters-optional-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-gnome-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-gnome-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-cs-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-da-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-de-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-en-GB-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-en-US-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-en-ZA-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-es-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-et-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-fr-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-gl-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-gu-IN-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-hi-IN-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-hu-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-it-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-ja-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-km-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-ko-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-nl-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-pl-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-pt-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-pt-BR-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-ru-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-sl-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-sv-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-zh-CN-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-help-zh-TW-3.5.4.13-1.4.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-icon-theme-crystal-3.5.4.13-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-icon-theme-galaxy-3.5.4.13-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-icon-theme-hicontrast-3.5.4.13-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-icon-theme-oxygen-3.5.4.13-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-icon-theme-tango-3.5.4.13-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-icon-themes-prebuilt-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-impress-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-impress-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-impress-extensions-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-impress-extensions-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-kde-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-kde-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-kde4-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-kde4-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-af-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-ar-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-be-BY-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-bg-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-br-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-ca-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-cs-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-cy-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-da-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-de-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-el-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-en-GB-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-en-ZA-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-es-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-et-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-fi-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-fr-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-ga-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-gl-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-gu-IN-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-he-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-hi-IN-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-hr-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-hu-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-it-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-ja-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-ka-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-km-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-ko-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-lt-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-mk-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-nb-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-nl-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-nn-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-nr-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-pa-IN-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-pl-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-prebuilt-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-pt-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-pt-BR-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-ru-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-rw-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-sh-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-sk-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-sl-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-sr-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-ss-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-st-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-sv-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-tg-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-th-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-tr-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-ts-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-uk-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-ve-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-vi-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-xh-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-zh-CN-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-zh-TW-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-l10n-zu-3.5.4.13-1.4.8") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-mailmerge-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-math-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-math-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-officebean-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-officebean-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-pyuno-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-pyuno-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-sdk-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-sdk-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-writer-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-writer-debuginfo-3.5.4.13-1.4.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libreoffice-writer-extensions-3.5.4.13-1.4.5") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreoffice");
}
