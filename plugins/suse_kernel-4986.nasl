#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-4986.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(31089);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2007-6206", "CVE-2008-0600");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-4986)");
  script_summary(english:"Check for the kernel-4986 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

  - CVE-2008-0600: A local privilege escalation was found in
    the vmsplice_pipe system call, which could be used by
    local attackers to gain root access.

  - CVE-2007-6206: Core dumps from root might be accessible
    to the wrong owner.

And the following bugs (numbers are https://bugzilla.novell.com/
references) :

  - Update to minor kernel version 2.6.22.17

  - networking bugfixes

  - contains the following patches which were removed :

  - patches.arch/acpica-psd.patch

  - patches.fixes/invalid-semicolon

  - patches.fixes/nopage-range-fix.patch

  - patches.arch/acpi_thermal_blacklist_add_r50p.patch:
    Avoid critical temp shutdowns on specific Thinkpad R50p
    (https://bugzilla.novell.com/show_bug.cgi?id=333043).

  - Update config files. CONFIG_USB_DEBUG in debug kernel

  - patches.rt/megasas_IRQF_NODELAY.patch: Convert megaraid
    sas IRQ to non-threaded IRQ (337489).

  - patches.drivers/libata-implement-force-parameter added
    to series.conf.

  - patches.xen/xen3-fixup-arch-i386: xen3 i386 build fixes.

  - patches.xen/xenfb-module-param: Re: Patching Xen virtual
    framebuffer."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=333043"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"kernel-bigsmp-2.6.22.17-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-debug-2.6.22.17-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-default-2.6.22.17-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-rt-2.6.22.17-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-rt_debug-2.6.22.17-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-source-2.6.22.17-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-syms-2.6.22.17-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xen-2.6.22.17-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xenpae-2.6.22.17-0.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-bigsmp / kernel-debug / kernel-default / kernel-rt / etc");
}
