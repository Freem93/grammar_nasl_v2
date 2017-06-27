#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0106.
#

include("compat.inc");

if (description)
{
  script_id(100238);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/26 15:15:34 $");

  script_cve_id("CVE-2013-7446", "CVE-2015-1420", "CVE-2015-4700", "CVE-2015-5257", "CVE-2015-5707", "CVE-2015-6252", "CVE-2015-6937", "CVE-2015-9731", "CVE-2016-10088", "CVE-2016-10142", "CVE-2016-10229", "CVE-2016-2782", "CVE-2016-3140", "CVE-2016-3672", "CVE-2016-4482", "CVE-2016-4485", "CVE-2016-4580", "CVE-2016-7425", "CVE-2016-7910", "CVE-2016-8399", "CVE-2016-8633", "CVE-2016-8645", "CVE-2017-2583", "CVE-2017-2636", "CVE-2017-2647", "CVE-2017-5669", "CVE-2017-5986", "CVE-2017-6074", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-7184", "CVE-2017-7187", "CVE-2017-7895");
  script_bugtraq_id(72357, 75356);
  script_osvdb_id(117759, 123637, 125710, 126403, 127759, 128036, 130525, 130545, 135143, 135876, 136761, 137963, 138086, 138444, 144411, 146778, 147034, 147168, 148195, 148443, 150179, 150690, 152094, 152302, 152453, 152521, 152728, 152729, 153186, 153853, 154043, 154627, 154861, 156529, 156530, 157982);

  script_name(english:"OracleVM 3.2 : Unbreakable / etc (OVMSA-2017-0106)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - nfsd: stricter decoding of write-like NFSv2/v3 ops (J.
    Bruce Fields) [Orabug: 25986995] (CVE-2017-7895)

  - ocfs2/o2net: o2net_listen_data_ready should do nothing
    if socket state is not TCP_LISTEN (Tariq Saeed) [Orabug:
    25510857]

  - IB/CORE: sync the resouce access in fmr_pool (Wengang
    Wang) [Orabug: 23750748]

  - ipv6: Skip XFRM lookup if dst_entry in socket cache is
    valid (Jakub Sitnicki) [Orabug: 25534688]

  - uek-rpm: enable CONFIG_KSPLICE. (Jamie Iles) [Orabug:
    25549845]

  - ksplice: add sysctls for determining Ksplice features.
    (Jamie Iles) 

  - signal: protect SIGNAL_UNKILLABLE from unintentional
    clearing. (Jamie Iles) [Orabug: 25549845]

  - KVM: x86: fix emulation of 'MOV SS, null selector'
    (Paolo Bonzini) [Orabug: 25719676] (CVE-2017-2583)
    (CVE-2017-2583)

  - sctp: avoid BUG_ON on sctp_wait_for_sndbuf (Marcelo
    Ricardo Leitner) [Orabug: 25719811] (CVE-2017-5986)

  - tcp: avoid infinite loop in tcp_splice_read (Eric
    Dumazet) [Orabug: 25720815] (CVE-2017-6214)

  - USB: visor: fix null-deref at probe (Johan Hovold)
    [Orabug: 25796604] (CVE-2016-2782)

  - ipc/shm: Fix shmat mmap nil-page protection (Davidlohr
    Bueso) [Orabug: 25797014] (CVE-2017-5669)

  - vhost: actually track log eventfd file
    (Marc-Andr&eacute  Lureau) [Orabug: 25797056]
    (CVE-2015-6252)

  - xfrm_user: validate XFRM_MSG_NEWAE incoming ESN size
    harder (Andy Whitcroft) [Orabug: 25814664]
    (CVE-2017-7184)

  - xfrm_user: validate XFRM_MSG_NEWAE XFRMA_REPLAY_ESN_VAL
    replay_window (Andy Whitcroft) [Orabug: 25814664]
    (CVE-2017-7184)

  - KEYS: Remove key_type::match in favour of overriding
    default by match_preparse (David Howells) [Orabug:
    25823965] (CVE-2017-2647) (CVE-2017-2647)

  - USB: whiteheat: fix potential null-deref at probe (Johan
    Hovold) [Orabug: 25825107] (CVE-2015-5257)

  - RDS: fix race condition when sending a message on
    unbound socket (Quentin Casasnovas) [Orabug: 25871048]
    (CVE-2015-6937) (CVE-2015-6937)

  - udf: Check path length when reading symlink (Jan Kara)
    [Orabug: 25871104] (CVE-2015-9731)

  - udf: Treat symlink component of type 2 as / (Jan Kara)
    [Orabug: 25871104] (CVE-2015-9731)

  - udp: properly support MSG_PEEK with truncated buffers
    (Eric Dumazet) [Orabug: 25874741] (CVE-2016-10229)

  - block: fix use-after-free in seq file (Vegard Nossum)
    [Orabug: 25877531] (CVE-2016-7910)

  - RHEL: complement upstream workaround for CVE-2016-10142.
    (Quentin Casasnovas) [Orabug: 25765786] (CVE-2016-10142)
    (CVE-2016-10142)

  - net: ping: check minimum size on ICMP header length
    (Kees Cook) [Orabug: 25766914] (CVE-2016-8399)

  - ipv6: stop sending PTB packets for MTU < 1280 (Hagen
    Paul Pfeifer) [Orabug: 25765786] (CVE-2016-10142)

  - sg_write/bsg_write is not fit to be called under
    KERNEL_DS (Al Viro) [Orabug: 25765448] (CVE-2016-10088)

  - scsi: sg: check length passed to SG_NEXT_CMD_LEN (peter
    chang) [Orabug: 25752011] (CVE-2017-7187)

  - tty: n_hdlc: get rid of racy n_hdlc.tbuf (Alexander
    Popov) [Orabug: 25696689] (CVE-2017-2636)

  - TTY: n_hdlc, fix lockdep false positive (Jiri Slaby)
    [Orabug: 25696689] (CVE-2017-2636)

  - drivers/tty/n_hdlc.c: replace kmalloc/memset by kzalloc
    (Fabian Frederick) [Orabug: 25696689] (CVE-2017-2636)

  - list: introduce list_first_entry_or_null (Jiri Pirko)
    [Orabug: 25696689] (CVE-2017-2636)

  - firewire: net: guard against rx buffer overflows (Stefan
    Richter) [Orabug: 25451538] (CVE-2016-8633)

  - x86/mm/32: Enable full randomization on i386 and X86_32
    (Hector Marco-Gisbert) [Orabug: 25463929]
    (CVE-2016-3672)

  - x86 get_unmapped_area: Access mmap_legacy_base through
    mm_struct member (Radu Caragea) [Orabug: 25463929]
    (CVE-2016-3672)

  - sg_start_req: make sure that there's not too many
    elements in iovec (Al Viro) [Orabug: 25490377]
    (CVE-2015-5707)

  - tcp: take care of truncations done by sk_filter (Eric
    Dumazet) [Orabug: 25507232] (CVE-2016-8645)

  - rose: limit sk_filter trim to payload (Willem de Bruijn)
    [Orabug: 25507232] (CVE-2016-8645)

  - scsi: arcmsr: Buffer overflow in arcmsr_iop_message_xfer
    (Dan Carpenter) [Orabug: 25507330] (CVE-2016-7425)

  - x86: bpf_jit: fix compilation of large bpf programs
    (Alexei Starovoitov) [Orabug: 25507375] (CVE-2015-4700)

  - net: fix a kernel infoleak in x25 module (Kangjie Lu)
    [Orabug: 25512417] (CVE-2016-4580)

  - USB: digi_acceleport: do sanity checking for the number
    of ports (Oliver Neukum) [Orabug: 25512472]
    (CVE-2016-3140)

  - net/llc: avoid BUG_ON in skb_orphan (Eric Dumazet)
    [Orabug: 25682437] (CVE-2017-6345)

  - dccp: fix freeing skb too early for IPV6_RECVPKTINFO
    (Andrey Konovalov) [Orabug: 25598277] (CVE-2017-6074)

  - vfs: read file_handle only once in handle_to_path (Sasha
    Levin) [Orabug: 25388709] (CVE-2015-1420)

  - crypto: algif_hash - Only export and import on sockets
    with data (Herbert Xu) [Orabug: 25417807]

  - USB: usbfs: fix potential infoleak in devio (Kangjie Lu)
    [Orabug: 25462763] (CVE-2016-4482)

  - net: fix infoleak in llc (Kangjie Lu) [Orabug: 25462811]
    (CVE-2016-4485)

  - af_unix: Guard against other == sk in unix_dgram_sendmsg
    (Rainer Weikusat) [Orabug: 25464000] (CVE-2013-7446)

  - unix: avoid use-after-free in ep_remove_wait_queue
    (Rainer Weikusat) [Orabug: 25464000] (CVE-2013-7446)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2017-May/000728.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-2.6.39-400.295.2.el5uek")) flag++;
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-firmware-2.6.39-400.295.2.el5uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}


