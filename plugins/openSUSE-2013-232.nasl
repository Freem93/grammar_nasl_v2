#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-232.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74935);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/09/11 10:41:00 $");

  script_cve_id("CVE-2013-1842", "CVE-2013-1843");

  script_name(english:"openSUSE Security Update : typo3-cms-4_5/typo3-cms-4_6/typo3-cms-4_7 (openSUSE-SU-2013:0510-1)");
  script_summary(english:"Check for the openSUSE-2013-232 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Typo3 CMS versions were updated to receive security and bug fixes.

  - Raised to version 4.5.25

  - bugfix: External URL regression by jumpurl security fix
    (Helmut Hummel), t3#46071

  - Raised to version 4.5.24

  - Raise submodule pointer (TYPO3 Release Team)

  - security: Open redirection with jumpurl (Franz G. Jahn),
    t3#28587, bnc#808528, CVE-2013-1843

  - bugfix: Check minitems for TCAtree (Georg Ringer),
    t3#25003

  - bugfix: Keep hyphens in custom HTML5 attributes (Jigal
    van Hemert), t3#34371

  - Revert '[BUGFIX] FE session records are never removed'
    (Oliver Hader), t3#45570

  - security fix: Typo3 Extbase Framework SQL Injection,
    bnc#808528, CVE-2013-1842

  - Raised to version 4.5.23

  - Raise submodule pointer

  - bugfix: t3lib_iconWorks must check if array exists
    before using it, t3#24248

  - bugfix: BE user switch impossible when in adminOnly
    mode, t3#32686

  - bugfix: Excludefieds must exclude admin only tables,
    t3#34460

  - bugfix: TypoLink: absolute urls when installed in
    subfolder, t3#33214

  - Raise submodule pointer

  - bugfix: [Cache][PDO] Duplicate cache entry possible,
    t3#34129

  - bugfix: IE9 compatibility clear cache menu, t3#36364

  - bugfix: Hook call modifyDBRow in ContentContentObject,
    t3#44416

  - bugfix: Fix misspelling in RTE meta menu, t3#43886

  - bugfix: load TCA before manipulation, t3#38505

  - DataHandler::getAutoVersionId() should be public,
    t3#45050

  - bugfix: Load date-time picker in scheduler module,
    t3#31027

  - bugfix: Quick Edit triggers warnings of missing key uid,
    t3#42845

  - Raise submodule pointer

  - bugfix: Fix warnings in em on tab Maintenance, t3#39680

  - bugfix: Correct TCA inclusion for uploads rendering,
    t3#44145

  - bugfix: Update description on changed error reporting
    defaults, t3#38240

  - bugfix: Fix typos in stdWrap_crop description, t3#43919

  - bugfix: Apc Cache backend has side effects, t3#38135

  - bugfix: Invalid call to
    t3lib_TCEmain::processRemapStack(), t3#44301

  - Raise submodule pointer

  - bugfix: Suggest wizard is behind form inputs, t3#42092

  - bugfix: phpdoc: $urlParameters can be a string, t3#44263

  - bugfix: FE session records are never removed, t3#34964

  - bugfix: INTincScript_loadJSCode() causes PHP warnings,
    t3#32278

  - bugfix: Enable the RTE with WebKit version 534 on iOS
    and Android, t3#43603

  - bugfix: Remove HTML in RuntimeException from sysext
    'install', t3#38472

  - bugfix: Fix wrong column title in web>list for field
    colpos, t3#25113

  - bugfix: SqlParser: trim all kinds of whitespaces,
    t3#43470

  - Remove typo3.pageModule.js, t3#43459

  - bugfix: Installer: Reference images wrong, t3#42292

  - bugfix: Page Information shows incorrect number of total
    hits, t3#41608

  - bugfix: Old logo on 'Install Tool is locked' page,
    t3#42908

  - openid: Update php-openid to 2.2.2, t3#42236

  - Group excludefields by table, t3#34098

  - bugfix: Hide version selector if workspaces are used,
    t3#43264

  - Raise submodule pointer

  - Raised verstion to 4.6.18

  - bugfix: External URL regression by jumpurl security fix
    (Helmut Hummel), t3#46071

  - Raised version to 4.6.17

  - Raise submodule pointer (TYPO3 Release Team)

  - security: Open redirection with jumpurl (Franz G. Jahn),
    t3#28587, bnc#808528, CVE-2013-1843

  - security fix: Typo3 Extbase Framework SQL Injection,
    bnc#808528, CVE-2013-1842

  - Raised version to 4.6.16

  - bugfix: L10n fallback does not work for TS labels,
    t3#44099

  - bugfix: L10n fallback does not work for ExtJS in BE,
    t3#44273

  - Raise submodule pointer

  - bugfix: Allow 'en' as language key, t3#42084

  - Raise submodule pointer

  - bugfix: [Cache][PDO] Duplicate cache entry possible,
    t3#34129

  - bugfix: IE9 compatibility clear cache menu, t3#36364

  - bugfix: Hook call modifyDBRow in ContentContentObject,
    t3#44416

  - bugfix: Fix misspelling in RTE meta menu, t3#43886

  - bugfix: load TCA before manipulation, t3#38505

  - bugfix: add check for empty form values in FORM View,
    t3#28606

  - DataHandler::getAutoVersionId() should be public,
    t3#45050

  - bugfix: Quick Edit triggers warnings of missing key uid,
    t3#42845

  - Raise submodule pointer

  - bugfix: Fix warnings in em on tab Maintenance, t3#39680

  - bugfix: Correct TCA inclusion for uploads rendering,
    t3#44145

  - bugfix: Update description on changed error reporting
    defaults, t3#38240

  - bugfix: Fix typos in stdWrap_crop description, t3#43919

  - bugfix: Apc Cache backend has side effects, t3#38135

  - bugfix: Invalid call to
    t3lib_TCEmain::processRemapStack(), t3#44301

  - Raise submodule pointer

  - bugfix: Suggest wizard is behind form inputs, t3#42092

  - bugfix: phpdoc: $urlParameters can be a string, t3#44263

  - bugfix: FE session records are never removed, t3#34964

  - bugfix: INTincScript_loadJSCode() causes PHP warnings,
    t3#32278

  - bugfix: Fix broken logo file in Install Tool, t3#43426

  - bugfix: Remove HTML in RuntimeException from sysext
    'install', t3#38472

  - bugfix: Fix wrong column title in web>list for field
    colpos, t3#25113

  - bugfix: SqlParser: trim all kinds of whitespaces,
    t3#43470

  - Remove typo3.pageModule.js, t3#43459

  - bugfix: Installer: Reference images wrong, t3#42292

  - bugfix: Page Information shows incorrect number of total
    hits, t3#41608

  - bugfix: Old logo on 'Install Tool is locked' page,
    t3#42908

  - bugfix: Form values with newlines escaped in email,
    t3#32515

  - openid: Update php-openid to 2.2.2, t3#42236

  - bugfix: Wizard in HTML element moved to t3editor,
    t3#33813

  - bugfix: Livesearch toolbar should close others, t3#32890

  - bugfix: Hide version selector if workspaces are used,
    t3#43264

  - bugfix: Subject field in FormWizard, t3#35787

  - Raise submodule pointer

  - bugfix: Invalid behavior of search for integer in
    Backend search, t3#33700

  - fluid, bugfix: Unit test fails with broken timezone,
    t3#45285

  - fluid, bugfix: Date ViewHelper not using configured
    Timezones, t3#12769

  - fluid, bugfix: Fix typo and improve backup of system
    settings, t3#45218

  - fluid, bugfix: Remove PHP Error caused by setlocale
    call, t3#45118

  - fluid, bugfix: Incomplete locale backup in unit test,
    t3#44835

  - fluid, bugfix: selectViewHelper sorting should respect
    locales, t3#43445

  - fluid, bugfix: Image viewhelper clears $GLOBALS['TSFE']
    in backend context, t3#43446

  - fluid, bugfix: AbstractFormFieldViewHelper always
    converts entities, t3#34091

  - linkvalidator, bugfix: SQL error in getLinkCounts,
    t3#43322

  - version, bugfix: Catchable fatal error when using the
    swap button, t3#42948

  - Raised to version 4.7.10

  - bugfix: External URL regression by jumpurl security fix
    (Helmut Hummel), t3#46071

  - Added rpmlintrc to suppress duplicated files warning. 

  - Raised to version 4.7.9

  - Raise submodule pointer (TYPO3 Release Team)

  - security: Open redirection with jumpurl (Franz G. Jahn),
    t3#28587, bnc#808528, CVE-2013-1843

  - bugfix: Invalid RSA key when submitting form twice
    (Benjamin Mack), t3#40085

  - security fix: Typo3 Extbase Framework SQL Injection,
    bnc#808528, CVE-2013-1842

  - Raised to version 4.7.8

  - bugfix: L10n fallback does not work for TS labels,
    t3#44099

  - bugfix: L10n fallback does not work for ExtJS in BE,
    t3#44273

  - Raise submodule pointer

  - bugfix Allow 'en' as language key, t3#42084

  - Raise submodule pointer

  - bugfix: [Cache][PDO] Duplicate cache entry possible,
    t3#34129

  - bugfix: IE9 compatibility clear cache menu, t3#36364

  - bugfix: Hook call modifyDBRow in ContentContentObject,
    t3#44416

  - bugfix: Fix misspelling in RTE meta menu, t3#43886

  - bugfix: load TCA before manipulation, t3#38505

  - bugfix: add check for empty form values in FORM View,
    t3#28606

  - DataHandler::getAutoVersionId() should be public,
    t3#45050

  - bugfix: Possible warning in about module, t3#44892

  - bugfix: Quick Edit triggers warnings of missing key uid,
    t3#42845

  - Raise submodule pointer

  - bugfix: Fix warnings in em on tab Maintenance, t3#39680

  - bugfix: EXT:felogin: Multiple bugs with preserveGETvars,
    t3#19938

  - bugfix: Correct TCA inclusion for uploads rendering,
    t3#44145

  - bugfix: array_merge_recursive_overrule: __UNSET for
    array values, t3#43874

  - bugfix: Update description on changed error reporting
    defaults, t3#38240

  - bugfix: Fix typos in stdWrap_crop description, t3#43919

  - Add save only button to Scheduler task, t3#44152

  - bugfix: Apc Cache backend has side effects, t3#38135

  - bugfix: Invalid call to
    t3lib_TCEmain::processRemapStack(), t3#44301

  - Raise submodule pointer

  - Suggest wizard is behind form inputs, t3#42092

  - bugfix: phpdoc: $urlParameters can be a string, t3#44263

  - bugfix: FE session records are never removed, t3#34964

  - bugfix: INTincScript_loadJSCode() causes PHP warnings,
    t3#32278

  - bugfix: Fix broken logo file in Install Tool, t3#43426

  - bugfix: Enable the RTE with WebKit version 534 on iOS
    and Android, t3#43603

  - bugfix: IE9 crashes after saving with RTE, t3#43766

  - bugfix: Remove HTML in RuntimeException from sysext
    'install', t3#38472

  - bugfix: Compatibility fix for
    get_html_translation_table(), t3#39287

  - bugfix: Fix wrong column title in web>list for field
    colpos, t3#25113

  - bugfix: SqlParser: trim all kinds of whitespaces,
    t3#43470

  - Remove typo3.pageModule.js, t3#43459

  - bugfix: Installer: Reference images wrong, t3#42292

  - bugfix: Page Information shows incorrect number of total
    hits, t3#41608

  - bugfix: Old logo on 'Install Tool is locked' page,
    t3#42908

  - bugfix: Form values with newlines escaped in email,
    t3#32515

  - openid: Update php-openid to 2.2.2, t3#42236

  - bugfix: Hide version selector if workspaces are used.
    t3#43264

  - bugfix: Subject field in FormWizard, t3#35787

  - Raise submodule pointer

  - Invalid behavior of search for integer in Backend
    search, t3#33700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-03/msg00079.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808528"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected typo3-cms-4_5/typo3-cms-4_6/typo3-cms-4_7 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typo3-cms-4_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typo3-cms-4_6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typo3-cms-4_7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"typo3-cms-4_5-4.5.25-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"typo3-cms-4_6-4.6.18-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"typo3-cms-4_7-4.7.10-2.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "typo3-cms-4_5/typo3-cms-4_6/typo3-cms-4_7");
}
