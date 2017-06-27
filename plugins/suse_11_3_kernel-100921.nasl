#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-3173.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75550);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/15 16:41:30 $");

  script_cve_id("CVE-2010-2955", "CVE-2010-2960", "CVE-2010-3079", "CVE-2010-3080", "CVE-2010-3081", "CVE-2010-3084", "CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3298", "CVE-2010-3301");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2010:0655-1)");
  script_summary(english:"Check for the kernel-3173 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of the openSUSE 11.3 kernel fixes two local root exploits,
various other security issues and some bugs.

Following security issues are fixed by this update: CVE-2010-3301:
Mismatch between 32bit and 64bit register usage in the system call
entry path could be used by local attackers to gain root privileges.
This problem only affects x86_64 kernels.

CVE-2010-3081: Incorrect buffer handling in the biarch-compat buffer
handling could be used by local attackers to gain root privileges.
This problem affects foremost x86_64, or potentially other biarch
platforms, like PowerPC and S390x.

CVE-2010-3084: A buffer overflow in the ETHTOOL_GRXCLSRLALL code could
be used to crash the kernel or potentially execute code.

CVE-2010-2955: A kernel information leak via the WEXT ioctl was fixed.

CVE-2010-2960: The keyctl_session_to_parent function in
security/keys/keyctl.c in the Linux kernel expects that a certain
parent session keyring exists, which allows local users to cause a
denial of service (NULL pointer dereference and system crash) or
possibly have unspecified other impact via a KEYCTL_SESSION_TO_PARENT
argument to the keyctl function.

CVE-2010-3080: A double free in an alsa error path was fixed, which
could lead to kernel crashes.

CVE-2010-3079: Fixed a ftrace NULL pointer dereference problem which
could lead to kernel crashes.

CVE-2010-3298: Fixed a kernel information leak in the net/usb/hso
driver.

CVE-2010-3296: Fixed a kernel information leak in the cxgb3 driver.

CVE-2010-3297: Fixed a kernel information leak in the net/eql driver."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-09/msg00042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=634637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=635413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=635425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=637502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=638274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=638277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639728"
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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-base-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-debug-devel-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-base-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-default-devel-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-base-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-desktop-devel-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-devel-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-base-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-devel-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-ec2-extra-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-base-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-pae-devel-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-source-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-source-vanilla-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-syms-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-base-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-trace-devel-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-base-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vanilla-devel-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-base-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-vmi-devel-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-base-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"kernel-xen-devel-2.6.34.7-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"preload-kmp-default-1.1_k2.6.34.7_0.3-19.1.3") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"preload-kmp-desktop-1.1_k2.6.34.7_0.3-19.1.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
