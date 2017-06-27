#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-661.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79268);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/17 12:17:37 $");

  script_cve_id("CVE-2014-3693");

  script_name(english:"openSUSE Security Update : libreoffice (openSUSE-SU-2014:1412-1)");
  script_summary(english:"Check for the openSUSE-2014-661 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libreoffice was updated to fix two security issues. &#9; These
security issues were fixed :

  - 'Document as E-mail' vulnerability (bnc#900218).

  - Impress Remote Control Use-after-Free Vulnerability
    (CVE-2014-3693)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00049.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900218"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreoffice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-en-US");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-en-ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-help-vi");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ast");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-om");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pa-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ug");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/17");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-base-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-base-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-base-drivers-mysql-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-base-drivers-mysql-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-base-drivers-postgresql-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-base-drivers-postgresql-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-base-extensions-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-branding-upstream-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-calc-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-calc-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-calc-extensions-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-debugsource-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-draw-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-draw-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-draw-extensions-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-filters-optional-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-gnome-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-gnome-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-ast-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-bg-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-ca-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-cs-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-da-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-de-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-el-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-en-GB-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-en-US-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-en-ZA-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-es-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-et-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-eu-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-fi-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-fr-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-gl-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-gu-IN-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-hi-IN-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-hu-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-it-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-ja-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-km-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-ko-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-mk-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-nb-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-nl-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-pl-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-pt-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-pt-BR-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-ru-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-sk-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-sl-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-sv-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-tr-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-vi-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-zh-CN-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-help-zh-TW-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-icon-theme-crystal-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-icon-theme-galaxy-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-icon-theme-hicontrast-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-icon-theme-oxygen-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-icon-theme-tango-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-icon-themes-prebuilt-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-impress-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-impress-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-impress-extensions-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-impress-extensions-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-kde-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-kde-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-kde4-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-kde4-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-af-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-am-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-ar-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-as-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-ast-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-be-BY-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-bg-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-br-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-ca-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-cs-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-cy-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-da-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-de-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-el-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-en-GB-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-en-ZA-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-eo-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-es-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-et-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-eu-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-fi-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-fr-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-ga-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-gd-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-gl-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-gu-IN-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-he-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-hi-IN-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-hr-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-hu-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-id-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-is-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-it-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-ja-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-ka-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-km-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-kn-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-ko-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-lt-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-mk-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-ml-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-mr-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-nb-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-nl-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-nn-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-nr-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-om-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-or-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-pa-IN-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-pl-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-prebuilt-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-pt-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-pt-BR-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-ro-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-ru-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-rw-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-sh-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-sk-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-sl-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-sr-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-ss-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-st-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-sv-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-ta-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-te-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-tg-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-th-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-tr-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-ts-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-ug-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-uk-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-ve-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-vi-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-xh-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-zh-CN-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-zh-TW-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-l10n-zu-4.1.6.2-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-mailmerge-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-math-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-math-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-officebean-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-officebean-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-pyuno-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-pyuno-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-sdk-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-sdk-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-writer-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-writer-debuginfo-4.1.6.2-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libreoffice-writer-extensions-4.1.6.2-29.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreoffice-branding-upstream / libreoffice-help-en-US / etc");
}
