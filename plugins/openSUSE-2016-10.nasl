#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-10.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87772);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/01/07 14:50:55 $");

  script_cve_id("CVE-2015-8370");

  script_name(english:"openSUSE Security Update : grub2 (openSUSE-2016-10)");
  script_summary(english:"Check for the openSUSE-2016-10 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fix buffer overflows when reading username and password.
    (bsc#956631, CVE-2015-8370)

  - Check MS-DOS header to find PE file header. (bsc#954126)

  - Use dirname for copying Xen kernel and initrd to esp.
    (bsc#955493)

  - Fix reading password by grub2-mkpasswd-pbdk2 without
    controlling tty. (bsc#954519)

  - Add luks, gcry_rijndael and gcry_sha1 to signed EFI
    image to support LUKS partition in default setup.
    (bsc#917427, bsc#955609)

  - Expand list of grub.cfg search path in PV Xen guests for
    systems installed on btrfs snapshots. (bsc#946148,
    bsc#952539) This update was imported from the
    SUSE:SLE-12-SP1:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=774666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=917427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=946148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=952539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956631"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected grub2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-i386-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-i386-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-snapper-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-x86_64-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:grub2-x86_64-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/07");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"grub2-2.02~beta2-76.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"grub2-branding-upstream-2.02~beta2-76.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"grub2-debuginfo-2.02~beta2-76.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"grub2-i386-efi-2.02~beta2-76.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"grub2-i386-pc-2.02~beta2-76.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"grub2-snapper-plugin-2.02~beta2-76.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"grub2-x86_64-efi-2.02~beta2-76.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"grub2-x86_64-xen-2.02~beta2-76.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2 / grub2-branding-upstream / grub2-debuginfo / grub2-i386-efi / etc");
}
