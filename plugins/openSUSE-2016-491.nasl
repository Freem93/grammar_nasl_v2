#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-491.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90610);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/04/21 13:55:54 $");

  script_name(english:"openSUSE Security Update : apparmor (openSUSE-2016-491)");
  script_summary(english:"Check for the openSUSE-2016-491 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for apparmor updates some profiles. It is specifically
required for the Samba security update.

profile updates :

  - sbin.syslog-ng

  - usr.sbin.identd

  - usr.sbin.nscd (allows nscd paranoia mode)

  - usr.sbin.smbd

  - usr.sbin.smbldap-useradd

  - apache2.d/phpsysinfo updated abstractions :

  - aspell

  - base

  - cups-client

  - fonts

  - freedesktop.org

  - nameservice

  - p11-kit

  - php5

  - samba (including the changes needed for Samba 4.2.x)

  - ssl_certs

  - ssl_keys

  - ubuntu-browsers.d/java

  - ubuntu-browsers.d/multimedia

  - ubuntu-browsers.d/plugins-common

  - ubuntu-browsers.d/ubuntu-integration

  - ubuntu-email

  - ubuntu-helpers

  - user-mail

  - X"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.launchpad.net/bugs/1399027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905368"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apparmor packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_apparmor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-parser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-parser-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-profiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-utils-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapparmor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapparmor1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapparmor1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapparmor1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapparmor1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_apparmor-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_apparmor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_apparmor-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-apparmor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-apparmor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-apparmor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/21");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"apache2-mod_apparmor-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-mod_apparmor-debuginfo-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apparmor-debugsource-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apparmor-parser-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apparmor-parser-debuginfo-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apparmor-parser-lang-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apparmor-profiles-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apparmor-utils-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apparmor-utils-lang-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libapparmor-devel-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libapparmor1-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libapparmor1-debuginfo-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pam_apparmor-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pam_apparmor-debuginfo-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-apparmor-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-apparmor-debuginfo-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-apparmor-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-apparmor-debuginfo-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby-apparmor-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ruby-apparmor-debuginfo-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libapparmor1-32bit-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libapparmor1-debuginfo-32bit-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"pam_apparmor-32bit-2.8.4-4.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"pam_apparmor-debuginfo-32bit-2.8.4-4.20.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-mod_apparmor / apache2-mod_apparmor-debuginfo / etc");
}
