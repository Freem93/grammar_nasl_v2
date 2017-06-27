#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:265. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(70837);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/11/25 11:41:42 $");

  script_cve_id("CVE-2013-2015", "CVE-2013-4348", "CVE-2013-4350", "CVE-2013-4387", "CVE-2013-4470", "CVE-2013-4483");
  script_bugtraq_id(59512, 62405, 62696, 63359, 63445, 63536);
  script_xref(name:"MDVSA", value:"2013:265");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2013:265)");
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

The ipc_rcu_putref function in ipc/util.c in the Linux kernel before
3.10 does not properly manage a reference count, which allows local
users to cause a denial of service (memory consumption or system
crash) via a crafted application (CVE-2013-4483).

The skb_flow_dissect function in net/core/flow_dissector.c in the
Linux kernel through 3.12 allows remote attackers to cause a denial of
service (infinite loop) via a small value in the IHL field of a packet
with IPIP encapsulation (CVE-2013-4348).

The Linux kernel before 3.12, when UDP Fragmentation Offload (UFO) is
enabled, does not properly initialize certain data structures, which
allows local users to cause a denial of service (memory corruption and
system crash) or possibly gain privileges via a crafted application
that uses the UDP_CORK option in a setsockopt system call and sends
both short and long packets, related to the ip_ufo_append_data
function in net/ipv4/ip_output.c and the ip6_ufo_append_data function
in net/ipv6/ip6_output.c (CVE-2013-4470).

The ext4_orphan_del function in fs/ext4/namei.c in the Linux kernel
before 3.7.3 does not properly handle orphan-list entries for
non-journal filesystems, which allows physically proximate attackers
to cause a denial of service (system hang) via a crafted filesystem on
removable media, as demonstrated by the e2fsprogs
tests/f_orphan_extents_inode/image.gz test (CVE-2013-2015).

net/ipv6/ip6_output.c in the Linux kernel through 3.11.4 does not
properly determine the need for UDP Fragmentation Offload (UFO)
processing of small packets after the UFO queueing of a large packet,
which allows remote attackers to cause a denial of service (memory
corruption and system crash) or possibly have unspecified other impact
via network traffic that triggers a large response packet
(CVE-2013-4387).

The IPv6 SCTP implementation in net/sctp/ipv6.c in the Linux kernel
through 3.11.1 uses data structures and function calls that do not
trigger an intended configuration of IPsec encryption, which allows
remote attackers to obtain sensitive information by sniffing the
network (CVE-2013-4350).

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"cpupower-3.4.68-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-firmware-3.4.68-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-headers-3.4.68-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-3.4.68-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-devel-3.4.68-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-source-3.4.68-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower-devel-3.4.68-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower0-3.4.68-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perf-3.4.68-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
