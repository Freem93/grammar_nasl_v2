#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libapr-util1-1375.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(42232);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/13 19:49:35 $");

  script_cve_id("CVE-2009-2412");

  script_name(english:"openSUSE Security Update : libapr-util1 (libapr-util1-1375)");
  script_summary(english:"Check for the libapr-util1-1375 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of libapr-util1 and libapr1 fixes multiple integer
overflows that could probably be used to execute arbitrary code
remotely. (CVE-2009-2412)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=529591"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libapr-util1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-dbd-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-dbd-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-dbd-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr1-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/23");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"libapr-util1-1.3.4-13.3.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libapr-util1-dbd-mysql-1.3.4-13.3.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libapr-util1-dbd-pgsql-1.3.4-13.3.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libapr-util1-dbd-sqlite3-1.3.4-13.3.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libapr-util1-devel-1.3.4-13.3.2") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libapr1-1.3.3-12.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libapr1-devel-1.3.3-12.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapr1");
}
