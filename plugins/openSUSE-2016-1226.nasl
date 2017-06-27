#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1226.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94302);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/31 13:56:11 $");

  script_cve_id("CVE-2016-5501", "CVE-2016-5538", "CVE-2016-5605", "CVE-2016-5608", "CVE-2016-5610", "CVE-2016-5611", "CVE-2016-5613");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2016-1226)");
  script_summary(english:"Check for the openSUSE-2016-1226 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for virtualbox fixes the following issues :

  - Address CVE-2016-5501, CVE-2016-5538, CVE-2016-5605,
    CVE-2016-5608, CVE-2016-5610, CVE-2016-5611,
    CVE-2016-5613 (boo#1005621).

  - Reduce memory needs during build.

  - Version bump to 5.0.28 (released 2016-10-18 by Oracle)
    This is a maintenance release. The following items were
    fixed and/or added: NAT: Don't exceed the maximum number
    of 'search' suffixes. Patch from bug #15948. NAT: fixed
    parsing of port-forwarding rules with a name which
    contains a slash (bug #16002) NAT Network: when the host
    has only loopback nameserver that cannot be mapped to
    the guests (e.g. dnsmasq running on 127.0.1.1), make
    DHCP supply NAT Network DNS proxy as nameserver. Bridged
    Network: prevent flooding syslog with packet allocation
    error messages (bug #15569) USB: fixed a possible crash
    when detaching a USB device Audio: fixes for recording
    (Mac OS X hosts only) Audio: now using Audio Queues on
    Mac OS X hosts OVF: improve importing of VMs created by
    VirtualBox 5.1 VHDX: fixed cloning images with
    VBoxManage cloned (bug #14288) Storage: Fixed broken
    bandwidth limitation when the limit is very low (bug
    #14982) Serial: Fixed high CPU usage with certain USB to
    serial converters on Linux hosts (bug #7796) BIOS: fixed
    4bpp scanline calculation (bug #15787) VBoxManage: Don't
    try to set the medium type if there is no change (bug
    #13850) API: fixed initialization of SAS controllers
    (bug #15972) Linux hosts: don't use 32-bit legacy
    capabilities Linux hosts / guests: fix for kernels with
    CONFIG_CPUMASK_OFFSTACK set (bug #16020) Linux
    Additions: several fixes for X11 guests running non-root
    X servers Linux Additions: fix for Linux 4.7 (bug
    #15769) Linux Additions: fix for the display kmod driver
    with Linux 4.8 (bugs #15890 and #15896) Windows
    Additions: auto-resizing fixes for Windows 10 guests
    (bug #15257) Windows Additions: fixes for arranging the
    guest screens in multi-screen scenarios Windows
    Additions / VGA: if the guest's power management turns a
    virtual screen off, blank the corresponding VM window
    rather than hide the VM window Windows Additions: fixed
    a generic bug which could lead to freezing shared
    folders (bug #15662) 

  - Modify virtualbox-guest-preamble and
    virtualbox-host-preamble to obsolete old versions of the
    kernel modules. This change should fix the problem in
    (boo#983629)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983629"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-5.0.28-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-debuginfo-5.0.28-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-5.0.28-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debuginfo-5.0.28-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debugsource-5.0.28-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-devel-5.0.28-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-desktop-icons-5.0.28-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-5.0.28_k3.16.7_42-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-debuginfo-5.0.28_k3.16.7_42-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-5.0.28_k3.16.7_42-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-debuginfo-5.0.28_k3.16.7_42-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-5.0.28_k3.16.7_42-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-debuginfo-5.0.28_k3.16.7_42-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-5.0.28-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-debuginfo-5.0.28-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-5.0.28-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-debuginfo-5.0.28-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-5.0.28_k3.16.7_42-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-debuginfo-5.0.28_k3.16.7_42-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-5.0.28_k3.16.7_42-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-debuginfo-5.0.28_k3.16.7_42-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-5.0.28_k3.16.7_42-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-debuginfo-5.0.28_k3.16.7_42-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-source-5.0.28-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-5.0.28-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-debuginfo-5.0.28-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-5.0.28-54.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-debuginfo-5.0.28-54.1") ) flag++;

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
