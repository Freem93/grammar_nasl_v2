#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:155. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(77074);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id("CVE-2013-4514", "CVE-2014-0131", "CVE-2014-4027", "CVE-2014-4608", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-4699", "CVE-2014-4943");
  script_bugtraq_id(63509, 66101, 67985, 68162, 68163, 68164, 68170, 68214, 68224, 68411, 68683);
  script_xref(name:"MDVSA", value:"2014:155");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2014:155)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been found and corrected in the Linux
kernel :

Multiple buffer overflows in drivers/staging/wlags49_h2/wl_priv.c in
the Linux kernel before 3.12 allow local users to cause a denial of
service or possibly have unspecified other impact by leveraging the
CAP_NET_ADMIN capability and providing a long station-name string,
related to the (1) wvlan_uil_put_info and (2)
wvlan_set_station_nickname functions (CVE-2013-4514).

Use-after-free vulnerability in the skb_segment function in
net/core/skbuff.c in the Linux kernel through 3.13.6 allows attackers
to obtain sensitive information from kernel memory by leveraging the
absence of a certain orphaning operation (CVE-2014-0131).

The rd_build_device_space function in drivers/target/target_core_rd.c
in the Linux kernel before 3.14 does not properly initialize a certain
data structure, which allows local users to obtain sensitive
information from ramdisk_mcp memory by leveraging access to a SCSI
initiator (CVE-2014-4027).

Multiple integer overflows in the lzo1x_decompress_safe function in
lib/lzo/lzo1x_decompress_safe.c in the LZO decompressor in the Linux
kernel before 3.15.2 allow context-dependent attackers to cause a
denial of service (memory corruption) via a crafted Literal Run
(CVE-2014-4608).

Race condition in the tlv handler functionality in the
snd_ctl_elem_user_tlv function in sound/core/control.c in the ALSA
control implementation in the Linux kernel before 3.15.2 allows local
users to obtain sensitive information from kernel memory by leveraging
/dev/snd/controlCX access (CVE-2014-4652).

sound/core/control.c in the ALSA control implementation in the Linux
kernel before 3.15.2 does not ensure possession of a read/write lock,
which allows local users to cause a denial of service (use-after-free)
and obtain sensitive information from kernel memory by leveraging
/dev/snd/controlCX access (CVE-2014-4653).

The snd_ctl_elem_add function in sound/core/control.c in the ALSA
control implementation in the Linux kernel before 3.15.2 does not
check authorization for SNDRV_CTL_IOCTL_ELEM_REPLACE commands, which
allows local users to remove kernel controls and cause a denial of
service (use-after-free and system crash) by leveraging
/dev/snd/controlCX access for an ioctl call (CVE-2014-4654).

The snd_ctl_elem_add function in sound/core/control.c in the ALSA
control implementation in the Linux kernel before 3.15.2 does not
properly maintain the user_ctl_count value, which allows local users
to cause a denial of service (integer overflow and limit bypass) by
leveraging /dev/snd/controlCX access for a large number of
SNDRV_CTL_IOCTL_ELEM_REPLACE ioctl calls (CVE-2014-4655).

Multiple integer overflows in sound/core/control.c in the ALSA control
implementation in the Linux kernel before 3.15.2 allow local users to
cause a denial of service by leveraging /dev/snd/controlCX access,
related to (1) index values in the snd_ctl_add function and (2) numid
values in the snd_ctl_remove_numid_conflict function (CVE-2014-4656).

The sctp_association_free function in net/sctp/associola.c in the
Linux kernel before 3.15.2 does not properly manage a certain backlog
value, which allows remote attackers to cause a denial of service
(socket outage) via a crafted SCTP packet (CVE-2014-4667).

The Linux kernel before 3.15.4 on Intel processors does not properly
restrict use of a non-canonical value for the saved RIP address in the
case of a system call that does not use IRET, which allows local users
to leverage a race condition and gain privileges, or cause a denial of
service (double fault), via a crafted application that makes ptrace
and fork system calls (CVE-2014-4699).

The PPPoL2TP feature in net/l2tp/l2tp_ppp.c in the Linux kernel
through 3.15.6 allows local users to gain privileges by leveraging
data-structure differences between an l2tp socket and an inet socket
(CVE-2014-4943).

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"cpupower-3.4.100-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-firmware-3.4.100-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-headers-3.4.100-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-3.4.100-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-devel-3.4.100-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower-devel-3.4.100-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower0-3.4.100-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perf-3.4.100-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
