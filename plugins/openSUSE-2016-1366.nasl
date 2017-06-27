#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1366.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95378);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/11/29 14:25:51 $");

  script_cve_id("CVE-2016-5501", "CVE-2016-5538", "CVE-2016-5605", "CVE-2016-5608", "CVE-2016-5610", "CVE-2016-5611", "CVE-2016-5613");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2016-1366)");
  script_summary(english:"Check for the openSUSE-2016-1366 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for virtualbox fixes the following issues :

  - Fixes
    CVE-2016-5501,CVE-2016-5538,CVE-2016-5605,CVE-2016-5608,
    CVE-2016-5610,CVE-2016-5611,CVE-2016-5613 (bsc#1005621)

  - Add patch to limit number of simultaneous make jobs.

  - Version bump to 5.1.8 (released 2016-10-18 by Oracle)
    This is a maintenance release. The following items were
    fixed and/or added: GUI: fixed keyboard shortcut
    handling regressions (Mac OS X hosts only; bugs #15937
    and #15938) GUI: fixed keyboard handling regression for
    separate UI (Windows hosts only; bugs #15928) NAT: don't
    exceed the maximum number of 'search' suffixes. Patch
    from bug #15948. NAT: fixed parsing of port-forwarding
    rules with a name which contains a slash (bug #16002)
    NAT Network: when the host has only loopback nameserver
    that cannot be mapped to the guests (e.g. dnsmasq
    running on 127.0.1.1), make DHCP supply NAT Network DNS
    proxy as nameserver. Bridged Network: prevent flooding
    syslog with packet allocation error messages (bug
    #15569) Audio: now using Audio Queues on Mac OS X hosts
    Audio: fixed recording with the PulseAudio backend (5.1
    regression) Audio: various bugfixes Snapshots: fixed
    regression in 5.1.4 for deleting snapshots with several
    disks (bug #15831) Snapshots: crash fix and better error
    reporting when snapshot deletion failed Storage: some
    fixes for the NVMe emulation with Windows guests API:
    fixed initialization of SAS controllers (bug #15972)
    Build system: make it possible to build VBox on systems
    which default to Python 3 Windows Additions / VGA: if
    the guest's power management turns a virtual screen off,
    blank the corresponding VM window rather than hide the
    window Windows Additions: fixed a generic bug which
    could lead to freezing shared folders (bug #15662) Linux
    hosts / guests: fix for kernels with
    CONFIG_CPUMASK_OFFSTACK set (bug #16020) Linux
    Additions: don't require all virtual consoles be in text
    mode. This should fix cases when the guest is booted
    with a graphical boot screen (bug #15683) Linux
    Additions: added depmod overrides for the vboxguest and
    vboxsf kernel modules to fix conflicts with modules
    shipped by certain Linux distributions X11 Additions:
    disable 3D on the guest if the host does not provide
    enough capabilities (bug #15860) 

  - Builds keep running out of memory when building the web
    server part of the package. To help the memory pressure,
    I have forced make to run with '-j2', rather than use
    the number of processors. Such a change will slow the
    build, but will result in a higher rate of success.

  - Increase memory allowed in build to 10000 MB.

  - Remove file 'fix_removal_of_DEFINE_PCI_DEVICE_TABLE' -
    fixed upstream.

  - Version bump to 5.1.6 (released 2016-09-12 by Oracle)
    This is a maintenance release. The following items were
    fixed and/or added: GUI: fixed issue with opening
    '.vbox' files and it's aliases GUI: keyboard grabbing
    fixes (bugs #15771 and #15745) GUI: fix for passing
    through Ctrl + mouse-click (Mac OS X hosts only; bug
    #15714) GUI: fixed automatic deletion of extension pack
    files (bugs #11352 and #14742) USB: fixed showing
    unknown device instead of the manufacturer or product
    description under certain circumstances (5.1.0
    regression; bug #15764) XHCI: another fix for a hanging
    guest under certain conditions as result of the fix for
    bug #15747, this time for Windows 7 guests Serial: fixed
    high CPU usage with certain USB to serial converters on
    Linux hosts (bug #7796) Storage: fixed attaching stream
    optimized VMDK images (bug #14764) Storage: reject image
    variants which are unsupported by the backend (bug
    #7227) Storage: fixed loading saved states created with
    VirtualBox 5.0.10 and older when using a SCSI controller
    (bug #15865) Storage: fixed broken NVMe emulation if the
    host I/O cache setting is enabled Storage: fixed using
    multiple NVMe controllers if ICH9 is used NVMe: fixed a
    crash during reset which could happen under certain
    circumstances Audio: fixed microphone input (5.1.2
    regression; bugs #14386 and #15802) Audio: fixed crashes
    under certain conditions (5.1.0 regression; bug #15887
    and others) Audio: fixed recording with the ALSA backend
    (5.1 regression) Audio: fixed stream access mode with
    OSS backend (5.1 regression, thanks to Jung-uk Kim)
    E1000: do also return masked bits when reading the ICR
    register, this fixes booting from iPXE (5.1.2
    regression; bug #15846) BIOS: fixed 4bpp scanline
    calculation (bug #15787) API: relax the check for the
    version attribute in OVF/OVA appliances (bug #15856)
    Windows hosts: fixed crashes when terminating the VM
    selector or other VBox COM clients (bug #15726 and
    others) Linux Installer: fixed path to the documentation
    in .rpm packages (5.1.0 regression) Linux Installer:
    fixed the vboxdrv.sh script to prevent an SELinux
    complaint (bug #15816) Linux hosts: don't use 32-bit
    legacy capabilities Linux Additions: Linux 4.8 fix for
    the kernel display driver (bugs #15890 and #15896) Linux
    Additions: don't load the kernel modules provided by the
    Linux distribution but load the kernel modules from the
    official Guest Additions package instead (bug #15324)
    Linux Additions: fix dynamic resizing problems in recent
    Linux guests (bug #15875) User Manual: fixed error in
    the VBoxManage chapter for the getextradata enumerate
    example (bug #15862) 

  - Add file 'fix_removal_of_DEFINE_PCI_DEVICE_TABLE' to
    compile on kernel 4.8."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005621"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/29");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"python-virtualbox-5.1.8-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-virtualbox-debuginfo-5.1.8-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-5.1.8-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-debuginfo-5.1.8-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-debugsource-5.1.8-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-devel-5.1.8-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-desktop-icons-5.1.8-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-kmp-default-5.1.8_k4.4.27_2-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-kmp-default-debuginfo-5.1.8_k4.4.27_2-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-tools-5.1.8-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-tools-debuginfo-5.1.8-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-x11-5.1.8-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-x11-debuginfo-5.1.8-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-host-kmp-default-5.1.8_k4.4.27_2-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-host-kmp-default-debuginfo-5.1.8_k4.4.27_2-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-host-source-5.1.8-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-qt-5.1.8-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-qt-debuginfo-5.1.8-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-websrv-5.1.8-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-websrv-debuginfo-5.1.8-3.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-virtualbox / python-virtualbox-debuginfo / virtualbox / etc");
}
