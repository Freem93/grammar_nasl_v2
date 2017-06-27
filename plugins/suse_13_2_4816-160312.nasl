#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2016/03/23. Deprecated by openSUSE-2016-845.nasl.

include("compat.inc");

if (description)
{
  script_id(90090);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/03/24 15:22:04 $");

  script_name(english:"openSUSE Security Update : 4816 (4816-1) (deprecated)");
  script_summary(english:"Check for the 4816-1 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Shotwell was updated to fix the following issues :

  - boo#958382: Shotwell did not perform TLS certificate
    verification when publishing photos to external services
    Also contains all upstream bug fixes and improvements in
    the current upstream version.

This plugin has been renamed to openSUSE-2016-845.nasl, plugin ID
90109."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958382"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shotwell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shotwell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shotwell-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shotwell-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use openSUSE-2016-845.nasl (plugin ID 90109) instead.");

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

if ( rpm_check(release:"SUSE13.2", reference:"shotwell-0.22.0+git.20160103-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"shotwell-debuginfo-0.22.0+git.20160103-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"shotwell-debugsource-0.22.0+git.20160103-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"shotwell-lang-0.22.0+git.20160103-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "shotwell / shotwell-debuginfo / shotwell-debugsource / etc");
}
