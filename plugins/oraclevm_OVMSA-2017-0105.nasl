#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0105.
#

include("compat.inc");

if (description)
{
  script_id(100237);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/26 15:15:34 $");

  script_cve_id("CVE-2015-5257", "CVE-2015-6252", "CVE-2015-9731", "CVE-2016-10088", "CVE-2016-10142", "CVE-2016-10208", "CVE-2016-10229", "CVE-2016-2782", "CVE-2016-7910", "CVE-2016-8399", "CVE-2016-9644", "CVE-2017-2583", "CVE-2017-2647", "CVE-2017-5669", "CVE-2017-5986", "CVE-2017-6214", "CVE-2017-7184", "CVE-2017-7187", "CVE-2017-7895");
  script_osvdb_id(126403, 128036, 130545, 135143, 146703, 147034, 147763, 148195, 148443, 150179, 150690, 152094, 152453, 152521, 153853, 154043, 154627, 154861, 156529, 156530, 157982);

  script_name(english:"OracleVM 3.3 : Unbreakable / etc (OVMSA-2017-0105)");
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
    Bruce Fields) [Orabug: 25986990] (CVE-2017-7895)

  - fnic: Update fnic driver version to 1.6.0.24 (John
    Sobecki) [Orabug: 24448585]

  - xen-netfront: Rework the fix for Rx stall during OOM and
    network stress (Dongli Zhang) [Orabug: 25450703]

  - xen-netfront: Fix Rx stall during network stress and OOM
    (Dongli Zhang) [Orabug: 25450703]

  - ipv6: Skip XFRM lookup if dst_entry in socket cache is
    valid (Jakub Sitnicki)

  - uek-rpm: enable CONFIG_KSPLICE. (Jamie Iles) [Orabug:
    25549809]

  - ksplice: add sysctls for determining Ksplice features.
    (Jamie Iles) 

  - signal: protect SIGNAL_UNKILLABLE from unintentional
    clearing. (Jamie Iles) [Orabug: 25549809]

  - VSOCK: Fix lockdep issue. (Dongli Zhang) [Orabug:
    25559937]

  - VSOCK: sock_put wasn't safe to call in interrupt context
    (Dongli Zhang) [Orabug: 25559937]

  - IB/CORE: sync the resouce access in fmr_pool (Wengang
    Wang) [Orabug: 25677469]

  - KVM: x86: fix emulation of 'MOV SS, null selector'
    (Paolo Bonzini) [Orabug: 25719675] (CVE-2017-2583)
    (CVE-2017-2583)

  - ext4: validate s_first_meta_bg at mount time (Eryu Guan)
    [Orabug: 25719738] (CVE-2016-10208)

  - sctp: avoid BUG_ON on sctp_wait_for_sndbuf (Marcelo
    Ricardo Leitner) [Orabug: 25719810] (CVE-2017-5986)

  - tcp: avoid infinite loop in tcp_splice_read (Eric
    Dumazet) [Orabug: 25720813] (CVE-2017-6214)

  - lpfc cannot establish connection with targets that send
    PRLI under P2P mode (Joe Jin) [Orabug: 25759083]

  - USB: visor: fix null-deref at probe (Johan Hovold)
    [Orabug: 25796594] (CVE-2016-2782)

  - ipc/shm: Fix shmat mmap nil-page protection (Davidlohr
    Bueso) [Orabug: 25797012] (CVE-2017-5669)

  - vhost: actually track log eventfd file
    (Marc-Andr&eacute  Lureau) [Orabug: 25797052]
    (CVE-2015-6252)

  - xfrm_user: validate XFRM_MSG_NEWAE incoming ESN size
    harder (Andy Whitcroft) [Orabug: 25814663]
    (CVE-2017-7184)

  - xfrm_user: validate XFRM_MSG_NEWAE XFRMA_REPLAY_ESN_VAL
    replay_window (Andy Whitcroft) [Orabug: 25814663]
    (CVE-2017-7184)

  - KEYS: Remove key_type::match in favour of overriding
    default by match_preparse (Aniket Alshi) [Orabug:
    25823962] (CVE-2017-2647) (CVE-2017-2647)

  - USB: whiteheat: fix potential null-deref at probe (Johan
    Hovold) [Orabug: 25825105] (CVE-2015-5257)
    (CVE-2015-5257)

  - udf: Check path length when reading symlink (Jan Kara)
    [Orabug: 25871102] (CVE-2015-9731)

  - udp: properly support MSG_PEEK with truncated buffers
    (Eric Dumazet) [Orabug: 25876655] (CVE-2016-10229)

  - block: fix use-after-free in seq file (Vegard Nossum)
    [Orabug: 25877530] (CVE-2016-7910)

  - Revert 'fix minor infoleak in get_user_ex' (Brian Maly)
    [Orabug: 25790392] (CVE-2016-9644)

  - net: ping: check minimum size on ICMP header length
    (Kees Cook) [Orabug: 25766911] (CVE-2016-8399)

  - ipv6: stop sending PTB packets for MTU < 1280 (Hagen
    Paul Pfeifer) [Orabug: 25765776] (CVE-2016-10142)

  - sg_write/bsg_write is not fit to be called under
    KERNEL_DS (Al Viro) [Orabug: 25765445] (CVE-2016-10088)

  - scsi: sg: check length passed to SG_NEXT_CMD_LEN (peter
    chang) [Orabug: 25751996] (CVE-2017-7187)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2017-May/000727.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

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
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-3.8.13-118.18.2.el6uek")) flag++;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-firmware-3.8.13-118.18.2.el6uek")) flag++;

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


