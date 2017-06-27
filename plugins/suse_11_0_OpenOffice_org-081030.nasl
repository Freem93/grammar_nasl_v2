#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update OpenOffice_org-288.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(39899);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 19:44:03 $");

  script_cve_id("CVE-2008-2237", "CVE-2008-2238");

  script_name(english:"openSUSE Security Update : OpenOffice_org (OpenOffice_org-288)");
  script_summary(english:"Check for the OpenOffice_org-288 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes an integer overflow in the WMF handler
(CVE-2008-2237) and multiple bugs in the EMF parser (CVE-2008-2238).
Additionally multiple non-security fixes were added."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=336242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=388802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=420323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=426403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=426894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=437304"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected OpenOffice_org packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-be-BY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-icon-themes-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-pa-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-sr-CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-testtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-zu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-af-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-ar-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-base-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-be-BY-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-bg-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-branding-upstream-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-ca-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-calc-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-cs-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-cy-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-da-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-de-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-devel-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-draw-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-el-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-en-GB-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-es-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-et-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-fi-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-filters-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-fr-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-gnome-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-gu-IN-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-hi-IN-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-hr-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-hu-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-icon-themes-prebuilt-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-impress-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-it-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-ja-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-kde-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-km-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-ko-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-lt-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-mailmerge-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-math-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-mk-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-mono-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-nb-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-nl-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-nn-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-officebean-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-pa-IN-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-pl-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-pt-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-pt-BR-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-pyuno-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-ru-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-rw-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-sdk-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-sk-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-sl-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-sr-CS-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-st-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-sv-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-testtool-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-tr-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-ts-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-vi-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-writer-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-xh-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-zh-CN-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-zh-TW-2.4.0.14-1.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-zu-2.4.0.14-1.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OOo");
}
