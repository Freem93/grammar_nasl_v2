#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-846.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87189);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/04 14:38:00 $");

  script_name(english:"openSUSE Security Update : dracut (openSUSE-2015-846)");
  script_summary(english:"Check for the openSUSE-2015-846 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dracut fixes the following issues :

  - Skip ibft setup via dhcp if dhcp ip is 0.0.0.0
    (boo#953361) Added
    0312-iscsi-skip-ibft-invalid-dhcp.patch

  - Modify
    0169-enabled-warning-for-failed-kernel-modules-per-defau
    l.patch

  - Add notice (boo#952491)

  - Refresh patches with line offsets: M
    0146-dracut.sh-corrected-logfile-check.patch M
    0182-fix_add_drivers_hang.patch M
    0183-kernel-modules-Fix-storage-module-selection-for-sdh
    c.patch

  - Modify 0181-load-xhci-pci.patch :

  - Add hid-logitech-hidpp

  - Ignore errors for xhci-pci, ehci-platform and
    hid-logitech-hidpp

  - Boo#952491, boo#935563 and boo#953035

  - Add 0311-less_pointless_module_errors.patch (boo#952491
    and boo#935563)

  - Don't warn if installing built-in modules fails

  - Don't print the error message twice

  - Modify
    0144-90crypt-fixed-crypttab_contains-to-also-work-with-d
    e.patch and
    0169-Enabled-Warning-for-failed-kernel-modules-per-defau
    l.patch

  - Fixes boo#935338

  - Use mktemp instead of hardcoded filenames, possible
    vulnerability"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=935338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=935563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=952491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953361"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dracut packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dracut-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dracut-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dracut-fips");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.1", reference:"dracut-037-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dracut-debuginfo-037-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dracut-debugsource-037-68.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"dracut-fips-037-68.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dracut / dracut-debuginfo / dracut-debugsource / dracut-fips");
}
