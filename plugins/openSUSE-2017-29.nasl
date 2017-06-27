#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-29.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96374);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/10 18:05:24 $");

  script_name(english:"openSUSE Security Update : syncthing / syncthing-gtk (openSUSE-2017-29)");
  script_summary(english:"Check for the openSUSE-2017-29 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This updates syncthing to version 0.14.16 and fixes the following
issues :

The following security issue was fixed :

  - A remote device that was already accepted by syncthing
    could perform arbitrary reads and writes outside of the
    configured directories (boo#1016161) This update also
    contains a number of upstream improvements in the
    0.14.14 version, including :

  - improved performance

  - UI improvements

  - prevention of data inconsistencies syncthing-gtk was
    updated to 0.9.2.3 to fix reading the configuration with
    non-ASCII locales. The new version is compatible with
    syncthing 0.14.x and includes various improvement and
    fixes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016161"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected syncthing / syncthing-gtk packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syncthing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syncthing-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syncthing-gtk-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/10");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"syncthing-0.14.16-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"syncthing-gtk-0.9.2.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"syncthing-gtk-lang-0.9.2.3-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "syncthing-gtk / syncthing-gtk-lang / syncthing");
}
