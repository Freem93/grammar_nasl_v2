#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-525.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99751);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/01 13:40:22 $");

  script_cve_id("CVE-2017-7572");

  script_name(english:"openSUSE Security Update : backintime (openSUSE-2017-525)");
  script_summary(english:"Check for the openSUSE-2017-525 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for backintime to version 1.1.20 fixes several issues.

These security issues were fixed :

  - CVE-2017-7572: The _checkPolkitPrivilege function in
    serviceHelper.py in backintime used a deprecated polkit
    authorization method (unix-process) that is subject to a
    race condition (time of check, time of use)
    (bsc#1032717).

  - Don't store passwords given to polkit helper

  - boo#1007723: General security hardening measures 

These non-security issues were fixed :

  - Delete udev configuration files on uninstall

  - Merge doc subpackage into main package"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032717"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected backintime packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:backintime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:backintime-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:backintime-qt4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"backintime-1.1.20-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"backintime-lang-1.1.20-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"backintime-qt4-1.1.20-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"backintime-1.1.20-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"backintime-lang-1.1.20-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"backintime-qt4-1.1.20-3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "backintime / backintime-lang / backintime-qt4");
}
