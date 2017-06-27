#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1451.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95757);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/13 18:01:19 $");

  script_cve_id("CVE-2016-7161", "CVE-2016-7170", "CVE-2016-7421", "CVE-2016-7466", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-8576", "CVE-2016-8577", "CVE-2016-8578", "CVE-2016-8667", "CVE-2016-8669", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9101", "CVE-2016-9102", "CVE-2016-9103", "CVE-2016-9104", "CVE-2016-9105", "CVE-2016-9106");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2016-1451)");
  script_summary(english:"Check for the openSUSE-2016-1451 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for qemu fixes the following issues :

  - Patch queue updated from
    https://gitlab.suse.de/virtualization/qemu.git SLE12-SP1

  - Change package post script udevadm trigger calls to be
    device specific (bsc#1002116)

  - Address various security/stability issues

  - Fix OOB access in xlnx.xpx-ethernetlite emulation
    (CVE-2016-7161 bsc#1001151)

  - Fix OOB access in VMware SVGA emulation (CVE-2016-7170
    bsc#998516)

  - Fix DOS in USB xHCI emulation (CVE-2016-7466
    bsc#1000345)

  - Fix DOS in Vmware pv scsi interface (CVE-2016-7421
    bsc#999661)

  - Fix DOS in ColdFire Fast Ethernet Controller emulation
    (CVE-2016-7908 bsc#1002550)

  - Fix DOS in USB xHCI emulation (CVE-2016-8576
    bsc#1003878)

  - Fix DOS in virtio-9pfs (CVE-2016-8578 bsc#1003894)

  - Fix DOS in virtio-9pfs (CVE-2016-9105 bsc#1007494)

  - Fix DOS in virtio-9pfs (CVE-2016-8577 bsc#1003893)

  - Plug data leak in virtio-9pfs interface (CVE-2016-9103
    bsc#1007454)

  - Fix DOS in virtio-9pfs interface (CVE-2016-9102
    bsc#1007450)

  - Fix DOS in virtio-9pfs (CVE-2016-9106 bsc#1007495)

  - Fix DOS in 16550A UART emulation (CVE-2016-8669
    bsc#1004707)

  - Fix DOS in PC-Net II emulation (CVE-2016-7909
    bsc#1002557)

  - Fix DOS in PRO100 emulation (CVE-2016-9101 bsc#1007391)

  - Fix DOS in RTL8139 emulation (CVE-2016-8910 bsc#1006538)

  - Fix DOS in Intel HDA controller emulation (CVE-2016-8909
    bsc#1006536)

  - Fix DOS in virtio-9pfs (CVE-2016-9104 bsc#1007493)

  - Fix DOS in JAZZ RC4030 emulation (CVE-2016-8667
    bsc#1004702)

  - Fix case of disk corruption with migration due to
    improper internal state tracking (bsc#996524)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=996524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://gitlab.suse.de/virtualization/qemu.git"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ipxe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/13");
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

if ( rpm_check(release:"SUSE42.1", reference:"qemu-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-arm-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-arm-debuginfo-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-block-curl-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-block-curl-debuginfo-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-debugsource-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-extra-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-extra-debuginfo-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-guest-agent-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-guest-agent-debuginfo-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-ipxe-1.0.0-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-kvm-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-lang-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-linux-user-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-linux-user-debuginfo-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-linux-user-debugsource-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-ppc-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-ppc-debuginfo-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-s390-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-s390-debuginfo-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-seabios-1.8.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-sgabios-8-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-tools-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-tools-debuginfo-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-vgabios-1.8.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-x86-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qemu-x86-debuginfo-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"qemu-block-rbd-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.3.1-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"qemu-testsuite-2.3.1-22.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-linux-user / qemu-linux-user-debuginfo / etc");
}
