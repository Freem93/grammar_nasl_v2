#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-4437.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75879);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/02 15:19:31 $");

  script_cve_id("CVE-2010-4650", "CVE-2011-0191", "CVE-2011-0521", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1082", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1163", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-1478", "CVE-2011-1493", "CVE-2011-1577", "CVE-2011-1581");
  script_osvdb_id(70665, 70950, 71519, 71604, 71653, 72995, 72996, 73037, 73038, 73039, 73046, 73049, 73053, 73054, 73290, 73291, 73882, 74636, 74637, 74638, 74639, 74640, 74641);

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2011:0416-1)");
  script_summary(english:"Check for the kernel-4437 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 11.4 kernel was updated to 2.6.37.6 fixing lots of bugs
and security issues.

Following security issues have been fixed: CVE-2011-1493: In the rose
networking stack, when parsing the FAC_NATIONAL_DIGIS facilities
field, it was possible for a remote host to provide more digipeaters
than expected, resulting in heap corruption. Check against
ROSE_MAX_DIGIS to prevent overflows, and abort facilities parsing on
failure.

CVE-2011-1182: Local attackers could send signals to their programs
that looked like coming from the kernel, potentially gaining
privileges in the context of setuid programs.

CVE-2011-1478: An issue in the core GRO code where an skb belonging to
an unknown VLAN is reused could result in a NULL pointer dereference.

CVE-2011-1476: Specially crafted requests may be written to
/dev/sequencer resulting in an underflow when calculating a size for a
copy_from_user() operation in the driver for MIDI interfaces. On x86,
this just returns an error, but it could have caused memory corruption
on other architectures. Other malformed requests could have resulted
in the use of uninitialized variables.

CVE-2011-1477: Due to a failure to validate user-supplied indexes in
the driver for Yamaha YM3812 and OPL-3 chips, a specially crafted
ioctl request could have been sent to /dev/sequencer, resulting in
reading and writing beyond the bounds of heap buffers, and potentially
allowing privilege escalation.

CVE-2011-0191: A information leak in the XFS geometry calls could be
used by local attackers to gain access to kernel information.

CVE-2011-0711: A stack memory information leak in the xfs
FSGEOMETRY_V1 ioctl was fixed.

CVE-2011-0521: The dvb_ca_ioctl function in
drivers/media/dvb/ttpci/av7110_ca.c in the Linux kernel did not check
the sign of a certain integer field, which allowed local users to
cause a denial of service (memory corruption) or possibly have
unspecified other impact via a negative value.

CVE-2011-1010: The code for evaluating Mac partitions (in
fs/partitions/mac.c) contained a bug that could crash the kernel for
certain corrupted Mac partitions.

CVE-2011-0712: Multiple buffer overflows in the caiaq Native
Instruments USB audio functionality in the Linux kernel might have
allowed attackers to cause a denial of service or possibly have
unspecified other impact via a long USB device name, related to (1)
the snd_usb_caiaq_audio_init function in sound/usb/caiaq/audio.c and
(2) the snd_usb_caiaq_midi_init function in sound/usb/caiaq/midi.c.

CVE-2011-1013: A signedness issue in the drm ioctl handling could be
used by local attackers to potentially overflow kernel buffers and
execute code.

CVE-2011-1082: The epoll subsystem in Linux did not prevent users from
creating circular epoll file structures, potentially leading to a
denial of service (kernel deadlock).

CVE-2010-4650: A kernel buffer overflow in the cuse server module was
fixed, which might have allowed local privilege escalation. However
only CUSE servers could exploit it and /dev/cuse is normally
restricted to root.

CVE-2011-1093: A bug was fixed in the DCCP networking stack where the
order of dccp_rcv_state_process() still permitted reception even after
closing the socket. A Reset after close thus causes a NULL pointer
dereference by not preventing operations on an already torn-down
socket.

CVE-2011-1163: The code for evaluating OSF partitions (in
fs/partitions/osf.c) contained a bug that leaks data from kernel heap
memory to userspace for certain corrupted OSF partitions.

CVE-2011-1012: The code for evaluating LDM partitions (in
fs/partitions/ldm.c) contained a bug that could crash the kernel for
certain corrupted LDM partitions.

CVE-2011-1581: Doing bridging with devices with more than 16 receive
queues could crash the kernel.

CVE-2011-1160: Kernel information via the TPM devices could by used by
local attackers to read kernel memory.

CVE-2011-1577: The Linux kernel automatically evaluated partition
tables of storage devices. The code for evaluating EFI GUID partitions
(in fs/partitions/efi.c) contained a bug that causes a kernel oops on
certain corrupted GUID partition tables, which might be used by local
attackers to crash the kernel or potentially execute code.

CVE-2011-1180: In the IrDA module, length fields provided by a peer
for names and attributes may be longer than the destination array
sizes and were not checked, this allowed local attackers (close to the
irda port) to potentially corrupt memory.

CVE-2011-1016: The Radeon GPU drivers in the Linux kernel did not
properly validate data related to the AA resolve registers, which
allowed local users to write to arbitrary memory locations associated
with (1) Video RAM (aka VRAM) or (2) the Graphics Translation Table
(GTT) via crafted values."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-04/msg00083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=554081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=558740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=607239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=610598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=644807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=648742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=667793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=668101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=668437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=668880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=669394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=669889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=669937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=672505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=672524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=673934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=673992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=674245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=674254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=674691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=674693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=674735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=676202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=677256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=677676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=677738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=679016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=679143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=679588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=679898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=680040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=680073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=680510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=680816"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=680932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=682725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=682965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=684112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=684248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=685469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=687113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=687116"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-base-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-base-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-debugsource-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-devel-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-devel-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-base-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-base-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-debugsource-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-devel-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-devel-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-base-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-base-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-debugsource-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-devel-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-devel-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-devel-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-base-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-base-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-debugsource-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-devel-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-devel-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-extra-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-extra-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-base-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-base-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-debugsource-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-devel-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-devel-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-source-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-source-vanilla-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-syms-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-base-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-base-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-debugsource-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-devel-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-devel-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-base-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-base-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-debugsource-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-devel-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-devel-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-base-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-base-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-debugsource-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-devel-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-devel-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-base-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-base-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-debugsource-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-devel-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-devel-debuginfo-2.6.37.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-default-1.2_k2.6.37.6_0.5-6.7.3") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-default-debuginfo-1.2_k2.6.37.6_0.5-6.7.3") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-desktop-1.2_k2.6.37.6_0.5-6.7.3") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-desktop-debuginfo-1.2_k2.6.37.6_0.5-6.7.3") ) flag++;

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
