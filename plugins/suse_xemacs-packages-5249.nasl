#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update xemacs-packages-5249.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(32441);
  script_version ("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/06/13 20:36:50 $");

  script_cve_id("CVE-2008-2142");

  script_name(english:"openSUSE 10 Security Update : xemacs-packages (xemacs-packages-5249)");
  script_summary(english:"Check for the xemacs-packages-5249 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Xemacs automatically loaded fast-lock files which allowed local
attackers to execute arbitrary code as the user editing the associated
files (CVE-2008-2142)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xemacs-packages packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xemacs-packages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xemacs-packages-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xemacs-packages-info");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"xemacs-packages-20051208-18.7") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xemacs-packages-el-20051208-18.7") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xemacs-packages-info-20051208-18.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xemacs-packages-20060510-30") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xemacs-packages-el-20060510-30") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xemacs-packages-info-20060510-30") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xemacs-packages-20070427-27.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xemacs-packages-el-20070427-27.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xemacs-packages-info-20070427-27.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xemacs-packages / xemacs-packages-el / xemacs-packages-info");
}
