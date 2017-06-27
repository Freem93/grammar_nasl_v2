#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1097.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93599);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2016-7162");

  script_name(english:"openSUSE Security Update : file-roller (openSUSE-2016-1097)");
  script_summary(english:"Check for the openSUSE-2016-1097 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for file-roller fixes the following issue :

  - CVE-2016-7162: Do not follow symlinks when deleting a
    folder recursively. (boo#997822, bgo#698554)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=997822"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected file-roller packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-roller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-roller-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-roller-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-roller-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nautilus-file-roller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nautilus-file-roller-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"file-roller-3.14.2-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"file-roller-debuginfo-3.14.2-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"file-roller-debugsource-3.14.2-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"file-roller-lang-3.14.2-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nautilus-file-roller-3.14.2-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nautilus-file-roller-debuginfo-3.14.2-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"file-roller-3.16.5-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"file-roller-debuginfo-3.16.5-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"file-roller-debugsource-3.16.5-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"file-roller-lang-3.16.5-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nautilus-file-roller-3.16.5-7.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nautilus-file-roller-debuginfo-3.16.5-7.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file-roller / file-roller-debuginfo / file-roller-debugsource / etc");
}
