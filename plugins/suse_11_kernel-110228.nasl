#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(52597);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/02 15:19:31 $");

  script_cve_id("CVE-2010-2943", "CVE-2010-3699", "CVE-2010-3705", "CVE-2010-3858", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-4075", "CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4163", "CVE-2010-4243", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4526", "CVE-2010-4527", "CVE-2010-4529", "CVE-2010-4650", "CVE-2010-4668", "CVE-2011-0006", "CVE-2011-0710", "CVE-2011-0711", "CVE-2011-0712");

  script_name(english:"SuSE 11.1 Security Update : Linux kernel (SAT Patch Numbers 4039 / 4042 / 4043)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 1 kernel was updated to
2.6.32.29 and fixes various bugs and security issues.

  - The ax25_getname function in net/ax25/af_ax25.c in the
    Linux kernel did not initialize a certain structure,
    which allowed local users to obtain potentially
    sensitive information from kernel stack memory by
    reading a copy of this structure. (CVE-2010-3875)

  - net/packet/af_packet.c in the Linux kernel did not
    properly initialize certain structure members, which
    allowed local users to obtain potentially sensitive
    information from kernel stack memory by leveraging the
    CAP_NET_RAW capability to read copies of the applicable
    structures. (CVE-2010-3876)

  - The get_name function in net/tipc/socket.c in the Linux
    kernel did not initialize a certain structure, which
    allowed local users to obtain potentially sensitive
    information from kernel stack memory by reading a copy
    of this structure. (CVE-2010-3877)

  - The sctp_auth_asoc_get_hmac function in net/sctp/auth.c
    in the Linux kernel did not properly validate the
    hmac_ids array of an SCTP peer, which allowed remote
    attackers to cause a denial of service (memory
    corruption and panic) via a crafted value in the last
    element of this array. (CVE-2010-3705)

  - A stack memory information leak in the xfs FSGEOMETRY_V1
    ioctl was fixed. (CVE-2011-0711)

  - Multiple buffer overflows in the caiaq Native
    Instruments USB audio functionality in the Linux kernel
    might have allowed attackers to cause a denial of
    service or possibly have unspecified other impact via a
    long USB device name, related to (1) the
    snd_usb_caiaq_audio_init function in
    sound/usb/caiaq/audio.c and (2) the
    snd_usb_caiaq_midi_init function in
    sound/usb/caiaq/midi.c. (CVE-2011-0712)

  - The task_show_regs function in arch/s390/kernel/traps.c
    in the Linux kernel on the s390 platform allowed local
    users to obtain the values of the registers of an
    arbitrary process by reading a status file under /proc/.
    (CVE-2011-0710)

  - The xfs implementation in the Linux kernel did not look
    up inode allocation btrees before reading inode buffers,
    which allowed remote authenticated users to read
    unlinked files, or read or overwrite disk blocks that
    are currently assigned to an active file but were
    previously assigned to an unlinked file, by accessing a
    stale NFS filehandle. (CVE-2010-2943)

  - The uart_get_count function in
    drivers/serial/serial_core.c in the Linux kernel did not
    properly initialize a certain structure member, which
    allowed local users to obtain potentially sensitive
    information from kernel stack memory via a TIOCGICOUNT
    ioctl call. (CVE-2010-4075)

  - The rs_ioctl function in drivers/char/amiserial.c in the
    Linux kernel did not properly initialize a certain
    structure member, which allowed local users to obtain
    potentially sensitive information from kernel stack
    memory via a TIOCGICOUNT ioctl call. (CVE-2010-4076)

  - The ntty_ioctl_tiocgicount function in
    drivers/char/nozomi.c in the Linux kernel did not
    properly initialize a certain structure member, which
    allowed local users to obtain potentially sensitive
    information from kernel stack memory via a TIOCGICOUNT
    ioctl call. (CVE-2010-4077)

  - fs/exec.c in the Linux kernel did not enable the OOM
    Killer to assess use of stack memory by arrays
    representing the (1) arguments and (2) environment,
    which allows local users to cause a denial of service
    (memory consumption) via a crafted exec system call, aka
    an OOM dodging issue, a related issue to CVE-2010-3858.
    (CVE-2010-4243)

  - The blk_rq_map_user_iov function in block/blk-map.c in
    the Linux kernel allowed local users to cause a denial
    of service (panic) via a zero-length I/O request in a
    device ioctl to a SCSI device, related to an unaligned
    map. NOTE: this vulnerability exists because of an
    incomplete fix for CVE-2010-4163. (CVE-2010-4668)

  - Integer underflow in the irda_getsockopt function in
    net/irda/af_irda.c in the Linux kernel on platforms
    other than x86 allowed local users to obtain potentially
    sensitive information from kernel heap memory via an
    IRLMP_ENUMDEVICES getsockopt call. (CVE-2010-4529)

  - The aun_incoming function in net/econet/af_econet.c in
    the Linux kernel, when Econet is enabled, allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and OOPS) by sending an Acorn Universal
    Networking (AUN) packet over UDP. (CVE-2010-4342)

  - The backend driver in Xen 3.x allowed guest OS users to
    cause a denial of service via a kernel thread leak,
    which prevented the device and guest OS from being shut
    down or create a zombie domain, causing a hang in
    zenwatch, or preventing unspecified xm commands from
    working properly, related to (1) netback, (2) blkback,
    or (3) blktap. (CVE-2010-3699)

  - The install_special_mapping function in mm/mmap.c in the
    Linux kernel did not make an expected security_file_mmap
    function call, which allows local users to bypass
    intended mmap_min_addr restrictions and possibly conduct
    NULL pointer dereference attacks via a crafted
    assembly-language application. (CVE-2010-4346)

  - Fixed a verify_ioctl overflow in 'cuse' in the fuse
    filesystem. The code should only be called by root users
    though. (CVE-2010-4650)

  - Race condition in the sctp_icmp_proto_unreachable
    function in net/sctp/input.c in the Linux kernel allowed
    remote attackers to cause a denial of service (panic)
    via an ICMP unreachable message to a socket that is
    already locked by a user, which causes the socket to be
    freed and triggers list corruption, related to the
    sctp_wait_for_connect function. (CVE-2010-4526)

  - The load_mixer_volumes function in sound/oss/soundcard.c
    in the OSS sound subsystem in the Linux kernel
    incorrectly expected that a certain name field ends with
    a '0' character, which allowed local users to conduct
    buffer overflow attacks and gain privileges, or possibly
    obtain sensitive information from kernel memory, via a
    SOUND_MIXER_SETLEVELS ioctl call. (CVE-2010-4527)

  - Fixed a LSM bug in IMA (Integrity Measuring
    Architecture). IMA is not enabled in SUSE kernels, so we
    were not affected. (CVE-2011-0006)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=466279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=552250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=564423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=602969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=620929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=622868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=623393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=625965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=629170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=630970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=632317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=633026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=636435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=638258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=640850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=642309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=643266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=643513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=648647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=648701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=648916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=649473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=650067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=650366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=650748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=651152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=652391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=655220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=655278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=655964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=657248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=657763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=658037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=658254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=658337"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=658353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=658461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=658551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=658720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=659101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=659394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=659419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=660546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=661605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=661945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=662945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=663537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=663582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=663706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=664149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=664463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=665480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=665499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=665524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=665663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=666012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=666893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=668545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=668633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=668929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=670129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=670577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=670864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=671256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=671274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=671483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=672292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=672492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=672499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=672524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=674735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2943.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3699.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3705.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3858.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3875.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3876.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3877.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4076.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4163.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4243.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4342.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4346.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4526.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4527.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4529.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4650.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4668.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0710.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0711.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0712.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 4039 / 4042 / 4043 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:btrfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:btrfs-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:btrfs-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:hyper-v-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:hyper-v-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"btrfs-kmp-default-0_2.6.32.29_0.3-0.3.34")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"btrfs-kmp-pae-0_2.6.32.29_0.3-0.3.34")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"btrfs-kmp-xen-0_2.6.32.29_0.3-0.3.34")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"hyper-v-kmp-default-0_2.6.32.29_0.3-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"hyper-v-kmp-pae-0_2.6.32.29_0.3-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-base-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-devel-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-extra-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-desktop-devel-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-base-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-devel-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-extra-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-source-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-syms-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-base-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-devel-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-extra-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"btrfs-kmp-default-0_2.6.32.29_0.3-0.3.34")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"btrfs-kmp-xen-0_2.6.32.29_0.3-0.3.34")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"hyper-v-kmp-default-0_2.6.32.29_0.3-0.10.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-base-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-devel-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-extra-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-desktop-devel-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-source-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-syms-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-base-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-devel-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-extra-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"btrfs-kmp-default-0_2.6.32.29_0.3-0.3.34")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"ext4dev-kmp-default-0_2.6.32.29_0.3-7.9.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-default-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-default-base-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-default-devel-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-source-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-syms-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-trace-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-trace-base-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-trace-devel-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"btrfs-kmp-pae-0_2.6.32.29_0.3-0.3.34")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"btrfs-kmp-xen-0_2.6.32.29_0.3-0.3.34")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"ext4dev-kmp-pae-0_2.6.32.29_0.3-7.9.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"ext4dev-kmp-xen-0_2.6.32.29_0.3-7.9.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"hyper-v-kmp-default-0_2.6.32.29_0.3-0.10.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"hyper-v-kmp-pae-0_2.6.32.29_0.3-0.10.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-ec2-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-ec2-base-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-pae-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-pae-base-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-pae-devel-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-xen-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-xen-base-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-xen-devel-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"kernel-default-man-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"btrfs-kmp-xen-0_2.6.32.29_0.3-0.3.34")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"ext4dev-kmp-xen-0_2.6.32.29_0.3-7.9.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"hyper-v-kmp-default-0_2.6.32.29_0.3-0.10.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-ec2-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-ec2-base-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-xen-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-xen-base-2.6.32.29-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-xen-devel-2.6.32.29-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
