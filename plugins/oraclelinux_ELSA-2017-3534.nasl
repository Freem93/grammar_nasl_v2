#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-3534.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(99160);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/07 15:07:05 $");

  script_cve_id("CVE-2013-7446", "CVE-2015-4700", "CVE-2015-5707", "CVE-2015-8569", "CVE-2016-10088", "CVE-2016-10142", "CVE-2016-3140", "CVE-2016-3672", "CVE-2016-4482", "CVE-2016-4485", "CVE-2016-4580", "CVE-2016-7425", "CVE-2016-8399", "CVE-2016-8633", "CVE-2016-8645", "CVE-2016-8646", "CVE-2016-9178", "CVE-2016-9588", "CVE-2016-9644", "CVE-2016-9793", "CVE-2017-2636", "CVE-2017-5970", "CVE-2017-6074", "CVE-2017-6345", "CVE-2017-7187");
  script_osvdb_id(123637, 125710, 130525, 131952, 135876, 136761, 137963, 138086, 138444, 144411, 146703, 146778, 147168, 147301, 148195, 148409, 148443, 148861, 150179, 151927, 152302, 152728, 152729, 153186, 154043);

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2017-3534)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[3.8.13-118.17.4.el7uek]
- Revert 'fix minor infoleak in get_user_ex()' (Brian Maly)  [Orabug: 
25790392]  {CVE-2016-9644}

[3.8.13-118.17.3.el7uek]
- net: ping: check minimum size on ICMP header length (Kees Cook) 
[Orabug: 25766911]  {CVE-2016-8399}

[3.8.13-118.17.2.el7uek]
- ipv6: stop sending PTB packets for MTU < 1280 (Hagen Paul Pfeifer) 
[Orabug: 25765776]  {CVE-2016-10142}
- sg_write()/bsg_write() is not fit to be called under KERNEL_DS (Al 
Viro)  [Orabug: 25765445]  {CVE-2016-10088}
- scsi: sg: check length passed to SG_NEXT_CMD_LEN (peter chang) 
[Orabug: 25751996]  {CVE-2017-7187}

[3.8.13-118.17.1.el7uek]
- tty: n_hdlc: get rid of racy n_hdlc.tbuf (Alexander Popov)  [Orabug: 
25696686]  {CVE-2017-2636}
- TTY: n_hdlc, fix lockdep false positive (Jiri Slaby)  [Orabug: 
25696686]  {CVE-2017-2636}
- drivers/tty/n_hdlc.c: replace kmalloc/memset by kzalloc (Fabian 
Frederick)  [Orabug: 25696686]  {CVE-2017-2636}
- x86: bpf_jit: fix compilation of large bpf programs (Alexei 
Starovoitov)  [Orabug: 21305080]  {CVE-2015-4700}
- net: filter: return -EINVAL if BPF_S_ANC* operation is not supported 
(Daniel Borkmann)  [Orabug: 22187148] - KEYS: request_key() should reget 
expired keys rather than give EKEYEXPIRED (David Howells)  - KEYS: 
Increase root_maxkeys and root_maxbytes sizes (Steve Dickson)  - 
firewire: net: guard against rx buffer overflows (Stefan Richter) 
[Orabug: 25451530]  {CVE-2016-8633}
- x86/mm/32: Enable full randomization on i386 and X86_32 (Hector 
Marco-Gisbert)  [Orabug: 25463927]  {CVE-2016-3672}
- x86 get_unmapped_area: Access mmap_legacy_base through mm_struct 
member (Radu Caragea)  [Orabug: 25463927]  {CVE-2016-3672}
- pptp: verify sockaddr_len in pptp_bind() and pptp_connect() (WANG 
Cong)  [Orabug: 25490335]  {CVE-2015-8569}
- sg_start_req(): make sure that there's not too many elements in iovec 
(Al Viro)  [Orabug: 25490372]  {CVE-2015-5707}
- kvm: nVMX: Allow L1 to intercept software exceptions (#BP and #OF) 
(Jim Mattson)  [Orabug: 25507195]  {CVE-2016-9588}
- tcp: take care of truncations done by sk_filter() (Eric Dumazet) 
[Orabug: 25507230]  {CVE-2016-8645}
- rose: limit sk_filter trim to payload (Willem de Bruijn)  [Orabug: 
25507230]  {CVE-2016-8645}
- fix minor infoleak in get_user_ex() (Al Viro)  [Orabug: 25507281] 
{CVE-2016-9178}
- scsi: arcmsr: Simplify user_len checking (Borislav Petkov)  [Orabug: 
25507328]  {CVE-2016-7425}
- scsi: arcmsr: Buffer overflow in arcmsr_iop_message_xfer() (Dan 
Carpenter)  [Orabug: 25507328]  {CVE-2016-7425}
- net: fix a kernel infoleak in x25 module (Kangjie Lu)  [Orabug: 
25512413]  {CVE-2016-4580}
- USB: digi_acceleport: do sanity checking for the number of ports 
(Oliver Neukum)  [Orabug: 25512471]  {CVE-2016-3140}
- ipv4: keep skb->dst around in presence of IP options (Eric Dumazet) 
[Orabug: 25543892]  {CVE-2017-5970}
- net/llc: avoid BUG_ON() in skb_orphan() (Eric Dumazet)  [Orabug: 
25682430]  {CVE-2017-6345}
- dccp: fix freeing skb too early for IPV6_RECVPKTINFO (Andrey 
Konovalov)   {CVE-2017-6074}
- crypto: algif_hash - Only export and import on sockets with data 
(Herbert Xu)  [Orabug: 25417805]  {CVE-2016-8646}
- USB: usbfs: fix potential infoleak in devio (Kangjie Lu)  [Orabug: 
25462760]  {CVE-2016-4482}
- net: fix infoleak in llc (Kangjie Lu)  [Orabug: 25462807]  {CVE-2016-4485}
- af_unix: Guard against other == sk in unix_dgram_sendmsg (Rainer 
Weikusat)  [Orabug: 25463996]  {CVE-2013-7446}
- unix: avoid use-after-free in ep_remove_wait_queue (Rainer Weikusat) 
[Orabug: 25463996]  {CVE-2013-7446}
- net: avoid signed overflows for SO_{SND|RCV}BUFFORCE (Eric Dumazet) 
[Orabug: 25203623]  {CVE-2016-9793}"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-April/006817.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-April/006818.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.17.4.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.17.4.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"dtrace-modules-3.8.13-118.17.4.el6uek-0.4.5-3.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-3.8.13-118.17.4.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-3.8.13-118.17.4.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-devel-3.8.13-118.17.4.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-devel-3.8.13-118.17.4.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-doc-3.8.13-118.17.4.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-firmware-3.8.13-118.17.4.el6uek")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"dtrace-modules-3.8.13-118.17.4.el7uek-0.4.5-3.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-3.8.13-118.17.4.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-3.8.13-118.17.4.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-3.8.13-118.17.4.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-3.8.13-118.17.4.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-3.8.13-118.17.4.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-firmware-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-firmware-3.8.13-118.17.4.el7uek")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
