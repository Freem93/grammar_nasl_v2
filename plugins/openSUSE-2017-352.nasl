#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-352.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97816);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/20 13:44:33 $");

  script_name(english:"openSUSE Security Update : irssi (openSUSE-2017-352)");
  script_summary(english:"Check for the openSUSE-2017-352 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to irssi 1.0.2 fixes security issues and bugs.

The following vulnerabilities were fixed :

boo#1029020: Use after free while producing list of netjoins

The following non-security changes are included :

  - Fix in command arg parser to detect missing arguments in
    tail place

  - Fix regression that broke incoming DCC file transfers

  - Fix issue with escaping \ in evaluated strings

  - improve UTF8 support in GRegex"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029020"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected irssi packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:irssi-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"irssi-1.0.2-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"irssi-debuginfo-1.0.2-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"irssi-debugsource-1.0.2-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"irssi-devel-1.0.2-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"irssi-1.0.2-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"irssi-debuginfo-1.0.2-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"irssi-debugsource-1.0.2-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"irssi-devel-1.0.2-15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irssi / irssi-debuginfo / irssi-debugsource / irssi-devel");
}
