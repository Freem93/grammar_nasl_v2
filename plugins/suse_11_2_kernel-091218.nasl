#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Updates.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(43631);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/21 20:21:19 $");

  script_cve_id(
    "CVE-2009-1298",
    "CVE-2009-3080",
    "CVE-2009-3547",
    "CVE-2009-3621",
    "CVE-2009-3624",
    "CVE-2009-3939",
    "CVE-2009-4005",
    "CVE-2009-4021",
    "CVE-2009-4026",
    "CVE-2009-4027",
    "CVE-2009-4131",
    "CVE-2009-4138",
    "CVE-2009-4306",
    "CVE-2009-4307",
    "CVE-2009-4308"
  );
  script_bugtraq_id(
    36723,
    36793,
    36901,
    37019,
    37036,
    37068,
    37069,
    37170,
    37231,
    37277,
    37339
  );
  script_osvdb_id(
    59210,
    59644,
    59654,
    60201,
    60311,
    60426,
    60558,
    60610,
    60788,
    60867,
    61026,
    61028,
    61035,
    61309
  );
  script_name(english:"SuSE 11.2 Security Update: kernel (2009-12-18)");
  script_summary(english:"Check for the kernel package.");

  script_set_attribute(attribute:"synopsis", value:"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Linux kernel for openSUSE 11.2 was updated to 2.6.31.8 to fix the
following bugs and security issues :

  - A file overwrite issue on the ext4 filesystem could be
    used by local attackers that have write access to a
    filesystem to change/overwrite files of other users,
    including root. (CVE-2009-4131)

  - A remote denial of service by sending overly long
    packets could be used by remote attackers to crash a
    machine. (CVE-2009-1298)

  - The mac80211 subsystem in the Linux kernel allows remote
    attackers to cause a denial of service (panic) via a
    crafted Delete Block ACK (aka DELBA) packet, related to
    an erroneous 'code shuffling patch.' (CVE-2009-4026)

  - Race condition in the mac80211 subsystem in the Linux
    kernel allows remote attackers to cause a denial of
    service (system crash) via a Delete Block ACK (aka
    DELBA) packet that triggers a certain state change in
    the absence of an aggregation session. (CVE-2009-4027)

  - The poll_mode_io file for the megaraid_sas driver in
    the Linux kernel has world-writable permissions, which
    allows local users to change the I/O mode of the driver
    by modifying this file. (CVE-2009-3939)

  - The collect_rx_frame function in
    drivers/isdn/hisax/hfc_usb.c in the Linux kernel allows
    attackers to have an unspecified impact via a crafted
    HDLC packet that arrives over ISDN and triggers a buffer
    under-read. This requires the attacker to access the
    machine on ISDN protocol level. (CVE-2009-4005)

  - Array index error in the gdth_read_event function in
    drivers/scsi/gdth.c in the Linux kernel allows local
    users to cause a denial of service or possibly gain
    privileges via a negative event index in an IOCTL
    request. (CVE-2009-3080)

  - The get_instantiation_keyring function in
    security/keys/keyctl.c in the KEYS subsystem in the
    Linux kernel does not properly maintain the reference
    count of a keyring, which allows local users to gain
    privileges or cause a denial of service (OOPS) via
    vectors involving calls to this function without
    specifying a keyring by ID, as demonstrated by a series
    of keyctl request2 and keyctl list commands.
    (CVE-2009-3624)

  - The fuse_direct_io function in fs/fuse/file.c in the
    fuse subsystem in the Linux kernel might allow attackers
    to cause a denial of service (invalid pointer
    dereference and OOPS) via vectors possibly related to a
    memory-consumption attack. (CVE-2009-4021)

  - Multiple race conditions in fs/pipe.c in the Linux
    kernel allow local users to cause a denial of service
    (NULL pointer dereference and system crash) or gain
    privileges by attempting to open an anonymous pipe via a
    /proc/*/fd/ pathname. As openSUSE 11.2 by default sets
    mmap_min_addr protection, this issue will just Oops the
    kernel and not be able to execute code. (CVE-2009-3547)

  - net/unix/af_unix.c in the Linux kernel allows local
    users to cause a denial of service (system hang) by
    creating an abstract-namespace AF_UNIX listening socket,
    performing a shutdown operation on this socket, and then
    performing a series of connect operations to this
    socket. (CVE-2009-3621)

  - drivers/firewire/ohci.c in the Linux kernel when
    packet-per-buffer mode is used, allows local users to
    cause a denial of service (NULL pointer dereference and
    system crash) or possibly have unknown other impact via
    an unspecified ioctl associated with receiving an ISO
    packet that contains zero in the payload-length field.
    (CVE-2009-4138)

  - The ext4_decode_error function in fs/ext4/super.c in
    the ext4 filesystem in the Linux kernel allows
    user-assisted remote attackers to cause a denial of
    service (NULL pointer dereference), and possibly have
    unspecified other impact, via a crafted read-only
    filesystem that lacks a journal. (CVE-2009-4308)

  - The ext4_fill_flex_info function in fs/ext4/super.c in
    the Linux kernel allows user-assisted remote attackers
    to cause a denial of service (divide-by-zero error and
    panic) via a malformed ext4 filesystem containing a
    super block with a large FLEX_BG group size (aka
    s_log_groups_per_flex value). (CVE-2009-4307)

  - Unspecified vulnerability in the EXT4_IOC_MOVE_EXT (aka
    move extents) ioctl implementation in the ext4
    filesystem in the Linux kernel allows local users to
    cause a denial of service (filesystem corruption) via
    unknown vectors, a different vulnerability than
    CVE-2009-4131. (CVE-2009-4306)

  - The EXT4_IOC_MOVE_EXT (aka move extents) ioctl
    implementation in the ext4 filesystem in the Linux
    kernel allows local users to overwrite arbitrary files
    via a crafted request, related to insufficient checks
    for file permissions. This can lead to privilege
    escalations. (CVE-2009-4131)

  - The rt2870 and rt2860 drivers were refreshed to the
    level they are in the Linux 2.6.32 kernel, bringing new
    device support and new functionality.");
  # http://lists.opensuse.org/opensuse-security-announce/2010-01/msg00000.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d661785");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=472410");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=498708");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=522790");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=523487");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=533555");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=533677");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=537081");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=539010");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=540589");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=540997");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=543407");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=543704");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=544779");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=546491");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=547357");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=548010");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=548728");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=549030");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=550787");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=551664");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=552033");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=552154");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=552492");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=556564");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=556568");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=556899");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=557180");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=557403");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=557668");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=557683");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=557760");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=558267");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=559062");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=559132");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=559680");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=560697");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=561018");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=561235");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=564712");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=559680");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=541736");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=561018");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=564382");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=564381");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=564380");
  script_set_attribute(attribute:"see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=561018");
  script_set_attribute(attribute:"solution", value:"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189, 264, 310, 362, 399);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/05");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"kernel-debug-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-debug-base-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-debug-devel-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-default-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-default-base-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-default-devel-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-desktop-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-desktop-base-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-desktop-devel-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-pae-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-pae-base-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-pae-devel-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-syms-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-trace-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-trace-base-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-trace-devel-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-vanilla-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-vanilla-base-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-vanilla-devel-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-xen-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-xen-base-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-xen-devel-2.6.31.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"preload-kmp-default-1.1_2.6.31.8_0.1-6.9.3") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"preload-kmp-desktop-1.1_2.6.31.8_0.1-6.9.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-devel / etc");
}
