#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-3535.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(99161);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/07 15:07:05 $");

  script_cve_id("CVE-2015-4700", "CVE-2015-5707", "CVE-2016-10088", "CVE-2016-10142", "CVE-2016-3140", "CVE-2016-3672", "CVE-2016-4580", "CVE-2016-7425", "CVE-2016-8399", "CVE-2016-8633", "CVE-2016-8645", "CVE-2017-2636", "CVE-2017-6345", "CVE-2017-7187");
  script_osvdb_id(123637, 125710, 135876, 136761, 138444, 144411, 146778, 147168, 148195, 148443, 150179, 152728, 152729, 153186, 154043);

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2017-3535)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[2.6.39-400.294.6.el6uek]
- RHEL: complement upstream workaround for CVE-2016-10142. (Quentin 
Casasnovas)  [Orabug: 25765786]  {CVE-2016-10142} {CVE-2016-10142}

[2.6.39-400.294.5.el6uek]
- net: ping: check minimum size on ICMP header length (Kees Cook) 
[Orabug: 25766914]  {CVE-2016-8399}
- ipv6: stop sending PTB packets for MTU < 1280 (Hagen Paul Pfeifer) 
[Orabug: 25765786]  {CVE-2016-10142}
- sg_write()/bsg_write() is not fit to be called under KERNEL_DS (Al 
Viro)  [Orabug: 25765448]  {CVE-2016-10088}
- scsi: sg: check length passed to SG_NEXT_CMD_LEN (peter chang) 
[Orabug: 25752011]  {CVE-2017-7187}

[2.6.39-400.294.4.el6uek]
- tty: n_hdlc: get rid of racy n_hdlc.tbuf (Alexander Popov)  [Orabug: 
25696689]  {CVE-2017-2636}
- TTY: n_hdlc, fix lockdep false positive (Jiri Slaby)  [Orabug: 
25696689]  {CVE-2017-2636}
- drivers/tty/n_hdlc.c: replace kmalloc/memset by kzalloc (Fabian 
Frederick)  [Orabug: 25696689]  {CVE-2017-2636}
- list: introduce list_first_entry_or_null (Jiri Pirko)  [Orabug: 
25696689]  {CVE-2017-2636}
- firewire: net: guard against rx buffer overflows (Stefan Richter) 
[Orabug: 25451538]  {CVE-2016-8633}
- x86/mm/32: Enable full randomization on i386 and X86_32 (Hector 
Marco-Gisbert)  [Orabug: 25463929]  {CVE-2016-3672}
- x86 get_unmapped_area: Access mmap_legacy_base through mm_struct 
member (Radu Caragea)  [Orabug: 25463929]  {CVE-2016-3672}
- sg_start_req(): make sure that there's not too many elements in iovec 
(Al Viro)  [Orabug: 25490377]  {CVE-2015-5707}
- tcp: take care of truncations done by sk_filter() (Eric Dumazet) 
[Orabug: 25507232]  {CVE-2016-8645}
- rose: limit sk_filter trim to payload (Willem de Bruijn)  [Orabug: 
25507232]  {CVE-2016-8645}
- scsi: arcmsr: Buffer overflow in arcmsr_iop_message_xfer() (Dan 
Carpenter)  [Orabug: 25507330]  {CVE-2016-7425}
- x86: bpf_jit: fix compilation of large bpf programs (Alexei 
Starovoitov)  [Orabug: 25507375]  {CVE-2015-4700}
- net: fix a kernel infoleak in x25 module (Kangjie Lu)  [Orabug: 
25512417]  {CVE-2016-4580}
- USB: digi_acceleport: do sanity checking for the number of ports 
(Oliver Neukum)  [Orabug: 25512472]  {CVE-2016-3140}
- net/llc: avoid BUG_ON() in skb_orphan() (Eric Dumazet)  [Orabug: 
25682437]  {CVE-2017-6345}"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-April/006819.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-April/006820.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-2.6.39-400.294.6.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-debug-2.6.39-400.294.6.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-devel-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-debug-devel-2.6.39-400.294.6.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-devel-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-devel-2.6.39-400.294.6.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-doc-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-doc-2.6.39-400.294.6.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-firmware-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-firmware-2.6.39-400.294.6.el5uek")) flag++;

if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-2.6.39-400.294.6.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-debug-2.6.39-400.294.6.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-debug-devel-2.6.39-400.294.6.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-devel-2.6.39-400.294.6.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-doc-2.6.39-400.294.6.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-firmware-2.6.39-400.294.6.el6uek")) flag++;


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
