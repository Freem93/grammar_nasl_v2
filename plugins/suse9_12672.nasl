#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(51953);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/21 20:33:29 $");

  script_cve_id("CVE-2010-2946", "CVE-2010-3067", "CVE-2010-3310", "CVE-2010-3442", "CVE-2010-3848", "CVE-2010-3849", "CVE-2010-3850", "CVE-2010-3873", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4081", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-4160", "CVE-2010-4164", "CVE-2010-4242", "CVE-2010-4258", "CVE-2010-4342", "CVE-2010-4527", "CVE-2010-4529");

  script_name(english:"SuSE9 Security Update : the Linux kernel (YOU Patch Number 12672)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This patch updates the SUSE Linux Enterprise Server 9 kernel to fix
various security issues and some bugs.

The following security issues were fixed :

  - The hci_uart_tty_open function in the HCI UART driver
    (drivers/bluetooth/hci_ldisc.c) in the Linux kernel did
    not verify whether the tty has a write operation, which
    allowed local users to cause a denial of service (NULL
    pointer dereference) via vectors related to the
    Bluetooth driver. (CVE-2010-4242)

  - The load_mixer_volumes function in sound/oss/soundcard.c
    in the OSS sound subsystem in the Linux kernel
    incorrectly expected that a certain name field ends with
    a '\0' character, which allowed local users to conduct
    buffer overflow attacks and gain privileges, or possibly
    obtain sensitive information from kernel memory, via a
    SOUND_MIXER_SETLEVELS ioctl call. (CVE-2010-4527)

  - Integer underflow in the irda_getsockopt function in
    net/irda/af_irda.c in the Linux kernel on platforms
    other than x86 allowed local users to obtain potentially
    sensitive information from kernel heap memory via an
    IRLMP_ENUMDEVICES getsockopt call. (CVE-2010-4529)

  - The aun_incoming function in net/econet/af_econet.c in
    the Linux kernel, when Econet is enabled, allowed remote
    attackers to cause a denial of service (NULL pointer
    dereference and OOPS) by sending an Acorn Universal
    Networking (AUN) packet over UDP. (CVE-2010-4342)

  - fs/jfs/xattr.c in the Linux kernel did not properly
    handle a certain legacy format for storage of extended
    attributes, which might have allowed local users by
    bypass intended xattr namespace restrictions via an
    'os2.' substring at the beginning of a name.
    (CVE-2010-2946)

  - Stack-based buffer overflow in the econet_sendmsg
    function in net/econet/af_econet.c in the Linux kernel,
    when an econet address is configured, allowed local
    users to gain privileges by providing a large number of
    iovec structures. (CVE-2010-3848)

  - The econet_sendmsg function in net/econet/af_econet.c in
    the Linux kernel, when an econet address is configured,
    allowed local users to cause a denial of service (NULL
    pointer dereference and OOPS) via a sendmsg call that
    specifies a NULL value for the remote address field.
    (CVE-2010-3849)

  - The ec_dev_ioctl function in net/econet/af_econet.c in
    the Linux kernel does not require the CAP_NET_ADMIN
    capability, which allowed local users to bypass intended
    access restrictions and configure econet addresses via
    an SIOCSIFADDR ioctl call. (CVE-2010-3850)

  - The do_exit function in kernel/exit.c in the Linux
    kernel did not properly handle a KERNEL_DS get_fs value,
    which allowed local users to bypass intended access_ok
    restrictions, overwrite arbitrary kernel memory
    locations, and gain privileges by leveraging a (1) BUG,
    (2) NULL pointer dereference, or (3) page fault, as
    demonstrated by vectors involving the clear_child_tid
    feature and the splice system call. (CVE-2010-4258)

  - Multiple integer overflows in the (1) pppol2tp_sendmsg
    function in net/l2tp/l2tp_ppp.c, and the (2)
    l2tp_ip_sendmsg function in net/l2tp/l2tp_ip.c, in the
    PPPoL2TP and IPoL2TP implementations in the Linux kernel
    allowed local users to cause a denial of service (heap
    memory corruption and panic) or possibly gain privileges
    via a crafted sendto call. (CVE-2010-4160)

  - Integer overflow in the ioc_general function in
    drivers/scsi/gdth.c in the Linux kernel on 64-bit
    platforms allowed local users to cause a denial of
    service (memory corruption) or possibly have unspecified
    other impact via a large argument in an ioctl call.
    (CVE-2010-4157)

  - Multiple integer underflows in the x25_parse_facilities
    function in net/x25/x25_facilities.c in the Linux kernel
    allowed remote attackers to cause a denial of service
    (system crash) via malformed X.25 (1) X25_FAC_CLASS_A,
    (2) X25_FAC_CLASS_B, (3) X25_FAC_CLASS_C, or (4)
    X25_FAC_CLASS_D facility data, a different vulnerability
    than CVE-2010-3873. (CVE-2010-4164)

  - The sk_run_filter function in net/core/filter.c in the
    Linux kernel did not check whether a certain memory
    location has been initialized before executing a (1)
    BPF_S_LD_MEM or (2) BPF_S_LDX_MEM instruction, which
    allowed local users to obtain potentially sensitive
    information from kernel stack memory via a crafted
    socket filter. (CVE-2010-4158)

  - Multiple integer overflows in the snd_ctl_new function
    in sound/core/control.c in the Linux kernel allowed
    local users to cause a denial of service (heap memory
    corruption) or possibly have unspecified other impact
    via a crafted (1) SNDRV_CTL_IOCTL_ELEM_ADD or (2)
    SNDRV_CTL_IOCTL_ELEM_REPLACE ioctl call. (CVE-2010-3442)

  - The snd_hdspm_hwdep_ioctl function in
    sound/pci/rme9652/hdspm.c in the Linux kernel did not
    initialize a certain structure, which allowed local
    users to obtain potentially sensitive information from
    kernel stack memory via an
    SNDRV_HDSPM_IOCTL_GET_CONFIG_INFO ioctl call.
    (CVE-2010-4081)

  - The ipc subsystem in the Linux kernel did not initialize
    certain structures, which allowed local users to obtain
    potentially sensitive information from kernel stack
    memory via vectors related to the (1) compat_sys_semctl,
    (2) compat_sys_msgctl, and (3) compat_sys_shmctl
    functions in ipc/compat.c; and the (4)
    compat_sys_mq_open and (5) compat_sys_mq_getsetattr
    functions in ipc/compat_mq.c. (CVE-2010-4073)

  - The copy_shmid_to_user function in ipc/shm.c in the
    Linux kernel did not initialize a certain structure,
    which allowed local users to obtain potentially
    sensitive information from kernel stack memory via
    vectors related to the shmctl system call and the 'old
    shm interface.'. (CVE-2010-4072)

  - The copy_semid_to_user function in ipc/sem.c in the
    Linux kernel did not initialize a certain structure,
    which allowed local users to obtain potentially
    sensitive information from kernel stack memory via a (1)
    IPC_INFO, (2) SEM_INFO, (3) IPC_STAT, or (4) SEM_STAT
    command in a semctl system call. (CVE-2010-4083)

  - Integer overflow in the do_io_submit function in
    fs/aio.c in the Linux kernel allowed local users to
    cause a denial of service or possibly have unspecified
    other impact via crafted use of the io_submit system
    call. (CVE-2010-3067)

  - Multiple integer signedness errors in net/rose/af_rose.c
    in the Linux kernel allowed local users to cause a
    denial of service (heap memory corruption) or possibly
    have unspecified other impact via a rose_getname
    function call, related to the rose_bind and rose_connect
    functions. (CVE-2010-3310)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2946.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3067.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3310.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3442.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3848.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3849.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3850.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3873.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4072.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4073.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4157.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4158.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4164.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4242.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4258.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4342.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4527.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4529.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12672.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-bigsmp-2.6.5-7.325")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-debug-2.6.5-7.325")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-default-2.6.5-7.325")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-smp-2.6.5-7.325")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-source-2.6.5-7.325")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-syms-2.6.5-7.325")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-um-2.6.5-7.325")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-xen-2.6.5-7.325")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-xenpae-2.6.5-7.325")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"um-host-install-initrd-1.0-48.38")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"um-host-kernel-2.6.5-7.325")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"xen-kmp-3.0.4_2.6.5_7.325-0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
