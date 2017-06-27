#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2011-57.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74530);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-4349");

  script_name(english:"openSUSE Security Update : colord (openSUSE-2011-57)");
  script_summary(english:"Check for the openSUSE-2011-57 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to version 0.1.15 :

  + This release fixes an important security bug:
    CVE-2011-4349.

  + New Features :

  - Add a native driver for the Hughski ColorHug hardware

  - Export cd-math as three projects are now using it

  + Bugfixes :

  - Documentation fixes and improvements

  - Do not crash the daemon if adding the device to the db
    failed

  - Do not match any sensor device with a kernel driver

  - Don't be obscure when the user passes a device-id to
    colormgr

  - Fix a memory leak when getting properties from a device

  - Fix colormgr device-get-default-profile

  - Fix some conection bugs in colormgr

  - Fix some potential SQL injections

  - Make gusb optional

  - Only use the udev USB helper if the PID and VID have
    matches

  - Output the Huey calibration matrices when dumping the
    sensor

  - Changes from version 0.1.14 :

  + New Features :

  - Add defines for the i1 Display 3

  - Add two more DATA_source values to the specification

  - Align the output from colormgr get-devices and
    get-profiles

  - Allow cd-fix-profile to append and edit new metadata

  + Bugfixes :

  - Ensure non-native device are added with no driver module

  - Split the sensor and device udev code

  + Updated translations.

  - Run the colord daemon as user colord :

  + Add colord-polkit-annotate-owner.patch: add
    org.freedesktop.policykit.owner annotations to policy
    file so that running as colord user works.

  + Add a %pre script to create the colord user.

  + Add pwdutils Requires(pre), to make sure we can create
    the user.

  + Pass --with-daemon-user=colord to configure.

  + Package /var/lib/colord with the right user.

  + Add calls to autoreconf and intltoolize, as needed by
    above patch."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732996"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected colord packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:colord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:colord-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:colord-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:colord-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcolord-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcolord1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcolord1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcolord1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcolord1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"colord-0.1.15-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"colord-debuginfo-0.1.15-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"colord-debugsource-0.1.15-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"colord-lang-0.1.15-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libcolord-devel-0.1.15-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libcolord1-0.1.15-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libcolord1-debuginfo-0.1.15-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libcolord1-32bit-0.1.15-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libcolord1-debuginfo-32bit-0.1.15-2.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "colord / colord-debuginfo / colord-debugsource / colord-lang / etc");
}
