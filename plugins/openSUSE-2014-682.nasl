#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-682.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79323);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/19 11:17:57 $");

  script_cve_id("CVE-2014-3693");

  script_name(english:"openSUSE Security Update : libreoffice (openSUSE-SU-2014:1443-1)");
  script_summary(english:"Check for the openSUSE-2014-682 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libreoffice was updated to version 4.3.3 to fix two security issues :

These security issues were fixed :

  - 'Document as E-mail' vulnerability (bnc#900218).

  - Impress remote control use-after-free vulnerability
    (CVE-2014-3693).

Various other fixes are included in the update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00070.html"
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
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900877"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-draw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-crystal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-galaxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-hicontrast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-sifr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-tango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-impress-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-kde4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-l10n-zh-Hant");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/19");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-base-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-base-debuginfo-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-base-drivers-mysql-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-base-drivers-mysql-debuginfo-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-base-drivers-postgresql-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-base-drivers-postgresql-debuginfo-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-branding-upstream-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-calc-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-calc-debuginfo-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-calc-extensions-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-debuginfo-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-debugsource-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-draw-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-draw-debuginfo-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-filters-optional-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-gnome-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-gnome-debuginfo-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-icon-theme-crystal-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-icon-theme-galaxy-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-icon-theme-hicontrast-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-icon-theme-oxygen-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-icon-theme-sifr-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-icon-theme-tango-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-impress-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-impress-debuginfo-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-kde4-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-kde4-debuginfo-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-af-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ar-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-as-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-bg-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-bn-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-br-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ca-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-cs-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-cy-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-da-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-de-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-dz-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-el-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-en-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-es-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-et-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-eu-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-fa-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-fi-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-fr-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ga-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-gl-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-gu-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-he-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-hi-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-hr-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-hu-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-it-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ja-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-kk-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-kn-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ko-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-lt-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-lv-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-mai-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ml-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-mr-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-nb-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-nl-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-nn-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-nr-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-nso-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-or-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-pa-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-pl-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-pt-BR-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-pt-PT-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ro-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ru-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-si-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-sk-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-sl-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-sr-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ss-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-st-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-sv-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ta-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-te-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-th-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-tn-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-tr-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ts-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-uk-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-ve-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-xh-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-zh-Hans-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-zh-Hant-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-l10n-zu-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-mailmerge-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-math-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-math-debuginfo-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-officebean-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-officebean-debuginfo-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-pyuno-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-pyuno-debuginfo-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-sdk-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-sdk-debuginfo-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-writer-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-writer-debuginfo-4.3.3.2-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libreoffice-writer-extensions-4.3.3.2-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreoffice / libreoffice-base / libreoffice-base-debuginfo / etc");
}
