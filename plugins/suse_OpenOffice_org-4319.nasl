#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update OpenOffice_org-4319.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27140);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/06/13 20:31:04 $");

  script_cve_id("CVE-2007-2834");

  script_name(english:"openSUSE 10 Security Update : OpenOffice_org (OpenOffice_org-4319)");
  script_summary(english:"Check for the OpenOffice_org-4319 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of OpenOffice_org fixes a bug in TIFF parsing code that
leads to a heap overflow. (CVE-2007-2834) This bug can be exploited
with user assistance to execute arbitrary code."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected OpenOffice_org packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-be-BY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-de-templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-en-GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-galleries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-gu-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-hi-IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-lt");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-sr-CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-zh-CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-zh-TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-zu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686)$") audit(AUDIT_ARCH_NOT, "i586 / i686", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-af-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-ar-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-be-BY-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-bg-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-ca-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-cs-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-cy-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-da-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-de-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-de-templates-8.2-171.9") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-el-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-en-GB-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-es-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-et-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-fi-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-fr-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-galleries-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-gnome-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-gu-IN-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-hi-IN-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-hr-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-hu-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-it-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-ja-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-kde-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-km-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-ko-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-lt-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-mk-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-mono-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-nb-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-nl-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-nn-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-officebean-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-pa-IN-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-pl-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-pt-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-pt-BR-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-ru-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-rw-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-sk-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-sl-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-sr-CS-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-st-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-sv-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-tr-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-ts-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-vi-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-xh-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-zh-CN-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-zh-TW-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"OpenOffice_org-zu-2.0.4-38.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-af-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-ar-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-be-BY-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-bg-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-ca-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-cs-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-cy-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-da-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-de-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-el-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-en-GB-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-es-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-et-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-fi-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-fr-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-galleries-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-gnome-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-gu-IN-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-hi-IN-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-hr-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-hu-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-it-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-ja-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-kde-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-km-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-ko-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-lt-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-mk-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-mono-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-nb-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-nl-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-nn-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-officebean-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-pa-IN-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-pl-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-pt-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-pt-BR-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-ru-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-rw-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-sdk-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-sk-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-sl-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-sr-CS-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-st-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-sv-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-tr-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-ts-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-vi-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-xh-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-zh-CN-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-zh-TW-2.0.4-38.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"OpenOffice_org-zu-2.0.4-38.7") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenOffice_org");
}
