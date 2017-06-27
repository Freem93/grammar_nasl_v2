#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1192.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94088);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/03/06 15:01:21 $");

  script_cve_id("CVE-2016-4324");

  script_name(english:"openSUSE Security Update : libreoffice (openSUSE-2016-1192)");
  script_summary(english:"Check for the openSUSE-2016-1192 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LibreOffice was updated to version 5.1.5.2, bringing enhancements and
bug fixes.

  - CVE-2016-4324: Parsing the Rich Text Format character
    style index was insufficiently checked for validity.
    Documents could be constructed which dereference an
    iterator to the first entry of an empty STL container.
    (bsc#987553)

  - Don't use 'nullable' for introspection, as it isn't
    available on SLE 12's version of gobject-introspection.
    This prevents a segmentation fault in gnome-documents.
    (bsc#1000102)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987553"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreoffice packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gdb-pretty-printers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-glade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreoffice-icon-theme-breeze");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreofficekit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreofficekit-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-base-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-base-debuginfo-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-base-drivers-mysql-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-base-drivers-mysql-debuginfo-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-base-drivers-postgresql-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-base-drivers-postgresql-debuginfo-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-branding-upstream-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-calc-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-calc-debuginfo-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-calc-extensions-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-debuginfo-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-debugsource-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-draw-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-draw-debuginfo-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-filters-optional-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-gdb-pretty-printers-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-glade-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-gnome-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-gnome-debuginfo-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-gtk3-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-gtk3-debuginfo-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-icon-theme-breeze-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-icon-theme-galaxy-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-icon-theme-hicontrast-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-icon-theme-oxygen-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-icon-theme-sifr-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-icon-theme-tango-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-impress-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-impress-debuginfo-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-kde4-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-kde4-debuginfo-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-af-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ar-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-as-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-bg-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-bn-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-br-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ca-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-cs-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-cy-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-da-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-de-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-dz-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-el-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-en-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-es-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-et-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-eu-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-fa-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-fi-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-fr-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ga-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-gl-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-gu-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-he-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-hi-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-hr-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-hu-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-it-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ja-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-kk-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-kn-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ko-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-lt-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-lv-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-mai-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ml-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-mr-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-nb-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-nl-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-nn-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-nr-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-nso-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-or-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-pa-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-pl-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-pt-BR-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-pt-PT-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ro-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ru-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-si-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-sk-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-sl-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-sr-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ss-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-st-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-sv-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ta-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-te-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-th-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-tn-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-tr-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ts-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-uk-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-ve-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-xh-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-zh-Hans-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-zh-Hant-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-l10n-zu-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-mailmerge-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-math-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-math-debuginfo-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-officebean-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-officebean-debuginfo-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-pyuno-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-pyuno-debuginfo-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-sdk-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-sdk-debuginfo-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-writer-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-writer-debuginfo-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreoffice-writer-extensions-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreofficekit-5.1.5.2-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libreofficekit-devel-5.1.5.2-11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreoffice / libreoffice-base / libreoffice-base-debuginfo / etc");
}
