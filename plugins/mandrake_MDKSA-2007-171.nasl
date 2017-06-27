#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:171. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(25968);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_cve_id("CVE-2006-5755", "CVE-2006-7203", "CVE-2007-1496", "CVE-2007-1497", "CVE-2007-1861", "CVE-2007-2172", "CVE-2007-2242", "CVE-2007-2453", "CVE-2007-2525", "CVE-2007-2875", "CVE-2007-2876");
  script_bugtraq_id(23615, 23870, 24376, 24390);
  script_xref(name:"MDKSA", value:"2007:171");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2007:171)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Some vulnerabilities were discovered and corrected in the Linux 2.6
kernel :

The Linux kernel did not properly save or restore EFLAGS during a
context switch, or reset the flags when creating new threads, which
allowed local users to cause a denial of service (process crash)
(CVE-2006-5755).

The compat_sys_mount function in fs/compat.c allowed local users to
cause a denial of service (NULL pointer dereference and oops) by
mounting a smbfs file system in compatibility mode (CVE-2006-7203).

The nfnetlink_log function in netfilter allowed an attacker to cause a
denial of service (crash) via unspecified vectors which would trigger
a NULL pointer dereference (CVE-2007-1496).

The nf_conntrack function in netfilter did not set nfctinfo during
reassembly of fragmented packets, which left the default value as
IP_CT_ESTABLISHED and could allow remote attackers to bypass certain
rulesets using IPv6 fragments (CVE-2007-1497).

The netlink functionality did not properly handle NETLINK_FIB_LOOKUP
replies, which allowed a remote attacker to cause a denial of service
(resource consumption) via unspecified vectors, probably related to
infinite recursion (CVE-2007-1861).

A typo in the Linux kernel caused RTA_MAX to be used as an array size
instead of RTN_MAX, which lead to an out of bounds access by certain
functions (CVE-2007-2172).

The IPv6 protocol allowed remote attackers to cause a denial of
service via crafted IPv6 type 0 route headers that create network
amplification between two routers (CVE-2007-2242).

The random number feature did not properly seed pools when there was
no entropy, or used an incorrect cast when extracting entropy, which
could cause the random number generator to provide the same values
after reboots on systems without an entropy source (CVE-2007-2453).

A memory leak in the PPPoE socket implementation allowed local users
to cause a denial of service (memory consumption) by creating a socket
using connect, and releasing it before the PPPIOCGCHAN ioctl is
initialized (CVE-2007-2525).

An integer underflow in the cpuset_tasks_read function, when the
cpuset filesystem is mounted, allowed local users to obtain kernel
memory contents by using a large offset when reading the
/dev/cpuset/tasks file (CVE-2007-2875).

The sctp_new function in netfilter allowed remote attackers to cause a
denial of service by causing certain invalid states that triggered a
NULL pointer dereference (CVE-2007-2876).

In addition to these security fixes, other fixes have been included
such as :

  - Fix crash on netfilter when nfnetlink_log is used on
    certain hooks on packets forwarded to or from a bridge

  - Fixed busy sleep on IPVS which caused high load averages

    - Fixed possible race condition on ext[34]_link

    - Fixed missing braces in condition block that led to
      wrong behaviour in NFS

  - Fixed XFS lock deallocation that resulted in oops when
    unmounting

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.17.15mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc-2.6.17.15mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.6.17.15mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-legacy-2.6.17.15mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-legacy-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.17.15mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-2.6.17.15mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xen0-2.6.17.15mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xen0-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xenU-2.6.17.15mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xenU-latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.0", reference:"kernel-2.6.17.15mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kernel-doc-2.6.17.15mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"kernel-enterprise-2.6.17.15mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"kernel-legacy-2.6.17.15mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kernel-source-2.6.17.15mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kernel-source-stripped-2.6.17.15mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kernel-xen0-2.6.17.15mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kernel-xenU-2.6.17.15mdv-1-1mdv2007.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2007.1", reference:"kernel-2.6.17.15mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-doc-2.6.17.15mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-doc-latest-2.6.17-15mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-enterprise-2.6.17.15mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-enterprise-latest-2.6.17-15mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-latest-2.6.17-15mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-legacy-2.6.17.15mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-legacy-latest-2.6.17-15mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-2.6.17.15mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-latest-2.6.17-15mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-stripped-2.6.17.15mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-stripped-latest-2.6.17-15mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xen0-2.6.17.15mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xen0-latest-2.6.17-15mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xenU-2.6.17.15mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xenU-latest-2.6.17-15mdv", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
