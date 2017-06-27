#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libpulse-browse0-2131.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(45103);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/06/13 20:00:36 $");

  script_cve_id("CVE-2009-1299");

  script_name(english:"openSUSE Security Update : libpulse-browse0 (libpulse-browse0-2131)");
  script_summary(english:"Check for the libpulse-browse0-2131 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Due to a race condition in pulseaudio a local attacker could make
pulseaudio change ownership and permissions of arbitrary files. The
problem is only security relevant if pulseaudio is run in 'system
mode' which is not the case by default (CVE-2009-1299).

This update also improves some latency problems with pulseaudio."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=555689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=584938"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpulse-browse0 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpulse-browse0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpulse-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpulse-mainloop-glib0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpulse0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpulse0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-esound-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-gdm-hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-gconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-lirc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"libpulse-browse0-0.9.21-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpulse-devel-0.9.21-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpulse-mainloop-glib0-0.9.21-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpulse0-0.9.21-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pulseaudio-0.9.21-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pulseaudio-esound-compat-0.9.21-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pulseaudio-gdm-hooks-0.9.21-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pulseaudio-lang-0.9.21-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pulseaudio-module-bluetooth-0.9.21-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pulseaudio-module-gconf-0.9.21-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pulseaudio-module-jack-0.9.21-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pulseaudio-module-lirc-0.9.21-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pulseaudio-module-x11-0.9.21-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pulseaudio-module-zeroconf-0.9.21-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"pulseaudio-utils-0.9.21-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"libpulse0-32bit-0.9.21-1.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpulse-browse0 / libpulse-devel / libpulse-mainloop-glib0 / etc");
}
