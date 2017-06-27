# @DEPRECATED@
#
# This script has been deprecated as the associated update is not
# for a supported release of Mandrake / Mandriva Linux.
#
# Disabled on 2012/09/06.
#

#
# (C) Tenable Network Security, Inc.
#
# This script was automatically generated from
# Mandrake Linux Security Advisory MDKSA-2005:220.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(20451);
  script_version ("$Revision: 1.11 $"); 
  script_cvs_date("$Date: 2014/08/22 19:56:33 $");

  script_cve_id("CVE-2005-1764", "CVE-2005-2098", "CVE-2005-2099", "CVE-2005-2456", "CVE-2005-2457", "CVE-2005-2458", "CVE-2005-2459", "CVE-2005-2490", "CVE-2005-2492", "CVE-2005-2800", "CVE-2005-2872", "CVE-2005-2873", "CVE-2005-3044", "CVE-2005-3053", "CVE-2005-3055", "CVE-2005-3179", "CVE-2005-3180", "CVE-2005-3181", "CVE-2005-3257", "CVE-2005-3271", "CVE-2005-3273", "CVE-2005-3274", "CVE-2005-3275", "CVE-2005-3276");

  script_name(english:"MDKSA-2005:220 : kernel");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities in the Linux 2.6 kernel have been discovered
and corrected in this update:

The kernel on x86_64 platforms does not use a guard page for the
47-bit address page to protect against an AMD K8 bug which allows a
local user to cause a DoS (CVE-2005-1764).

The KEYCTL_JOIN_SESSION_KEYRING operation in versions prior to
2.6.12.5 contains an error path that does not properly release the
session management semaphore, which allows local users or remote
attackers to cause a DoS (semaphore hang) via a new session keyring
with an empty name string, a long name string, the key quota reached,
or ENOMEM (CVE-2005-2098).

Kernels prior to 2.6.12.5 do not properly destroy a keyring that is
not instantiated properly, allowing a local user or remote attacker
to cause a DoS (oops) via a keyring with a payload that is not empty
(CVE-2005-2099).

An array index overflow in the xfrm_sk_policy_insert function in
xfrm_user.c allows local users to cause a DoS (oops or deadlock) and
possibly execute arbitrary code (CVE-2005-2456).

The zisofs driver in versions prior to 2.6.12.5 allows local users
and remove attackers to cause a DoS (crash) via a crafted compressed
ISO filesystem (CVE-2005-2457).

inflate.c in the zlib routines in versions prior to 2.6.12.5 allow
remove attackers to cause a DoS (crash) via a compressed file with
'improper tables' (CVE-2005-2458).

The huft_build function in inflate.c in the zlib routines in versions
prior to 2.6.12.5 returns the wrong value, allowing remote attackers
to cause a DoS (crash) via a certain compressed file that leads to a
NULL pointer dereference (CVE-2005-2459).

A stack-based buffer overflow in the sendmsg function call in
versions prior to 2.6.13.1 allow local users to execute arbitrary
code by calling sendmsg and modifying the message contents in another
thread (CVE-2005-2490).

The raw_sendmsg function in versions prior to 2.6.13.1 allow local
users to cause a DoS (change hardware state) or read from arbitrary
memory via crafted input (CVE-2005-2492).

A memory leak in the seq_file implementation in the SCSI procfs
interface (sg.c) in 2.6.13 and earlier allows a local user to cause a
DoS (memory consumption) via certain repeated reads from
/proc/scsi/gs/devices file which is not properly handled when the
next() interator returns NULL or an error (CVE-2005-2800).

The ipt_recent module in versions prior to 2.6.12 when running on
64bit processors allows remote attackers to cause a DoS (kernel
panic) via certain attacks such as SSH brute force (CVE-2005-2872).

The ipt_recent module in versions prior to 2.6.12 does not properly
perform certain tests when the jiffies value is greater than
LONG_MAX, which can cause ipt_recent netfilter rules to block too
early (CVE-2005-2873).

Multiple vulnerabilities in versions prior to 2.6.13.2 allow local
users to cause a DoS (oops from NULL dereference) via fput in a 32bit
ioctl on 64-bit x86 systems or sockfd_put in the 32-bit routing_ioctl
function on 64-bit systems (CVE-2005-3044).

The sys_set_mempolicy function in mempolicy.c allows local users to
cause a DoS via a negative first argument (CVE-2005-3053).

Versions 2.6.8 to 2.6.14-rc2 allow local users to cause a DoS (oops)
via a userspace process that issues a USB Request Block (URB) to a
USB device and terminates before the URB is finished, which leads to
a stale pointer reference (CVE-2005-3055).

drm.c in version 2.6.13 and earlier creates a debug file in sysfs
with world-readable and world-writable permissions, allowing local
users to enable DRM debugging and obtain sensitive information
(CVE-2005-3179).

The Orinoco driver in 2.6.13 and earlier does not properly clear
memory from a previously used packet whose length is increased,
allowing remote attackers to obtain sensitive information
(CVE-2005-3180).

Kernels 2.6.13 and earlier, when CONFIG_AUDITSYSCALL is enabled, use
an incorrect function to free names_cache memory, preventing the
memory from being tracked by AUDITSYSCALL code and leading to a
memory leak (CVE-2005-3181).

The VT implementation in version 2.6.12 allows local users to use
certain IOCTLs on terminals of other users and gain privileges
(CVE-2005-3257).

Exec does not properly clear posix-timers in multi-threaded
environments, which result in a resource leak and could allow a large
number of multiple local users to cause a DoS by using more posix-
timers than specified by the quota for a single user (CVE-2005-3271).

The rose_rt_ioctl function rose_route.c in versions prior to 2.6.12
does not properly verify the ndigis argument for a new route,
allowing an attacker to trigger array out-of-bounds errors with a
large number of digipeats (CVE-2005-3273).

A race condition in ip_vs_conn_flush in versions prior to 2.6.13,
when running on SMP systems, allows local users to cause a DoS (NULL
dereference) by causing a connection timer to expire while the
connection table is being flushed before the appropriate lock is
acquired (CVE-2005-3274).

The NAT code in versions prior to 2.6.13 incorrectly declares a
variable to be static, allowing remote attackers to cause a DoS
(memory corruption) by causing two packets for the same protocol to
be NATed at the same time (CVE-2005-3275).

The sys_get_thread_area function in process.c in versions prior to
2.6.12.4 and 2.6.13 does not clear a data structure before copying it
to userspace, which may allow a user process to obtain sensitive
information (CVE-2005-3276).

The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels.

To update your kernel, please follow the directions located at:

http://www.mandriva.com/en/security/kernelupdate");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKSA-2005:220");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cwe_id(399);
  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/30");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/15");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated update is not currently for a supported release of Mandrake / Mandriva Linux.");


include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Mandrake/release")) exit(0, "The host is not running Mandrake Linux.");
if (!get_kb_item("Host/Mandrake/rpm-list")) exit(1, "Could not get the list of packages.");

flag = 0;

if (rpm_check(reference:"kernel-2.6.11.13mdk-1-1mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kernel-i586-up-1GB-2.6.11.13mdk-1-1mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kernel-i686-up-4GB-2.6.11.13mdk-1-1mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kernel-smp-2.6.11.13mdk-1-1mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kernel-source-2.6-2.6.11-13mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kernel-source-stripped-2.6-2.6.11-13mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kernel-xbox-2.6.11.13mdk-1-1mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else 
{
  if (rpm_exists(rpm:"kernel-", release:"MDK10.2"))
  {
    set_kb_item(name:"CVE-2005-1764", value:TRUE);
    set_kb_item(name:"CVE-2005-2098", value:TRUE);
    set_kb_item(name:"CVE-2005-2099", value:TRUE);
    set_kb_item(name:"CVE-2005-2456", value:TRUE);
    set_kb_item(name:"CVE-2005-2457", value:TRUE);
    set_kb_item(name:"CVE-2005-2458", value:TRUE);
    set_kb_item(name:"CVE-2005-2459", value:TRUE);
    set_kb_item(name:"CVE-2005-2490", value:TRUE);
    set_kb_item(name:"CVE-2005-2492", value:TRUE);
    set_kb_item(name:"CVE-2005-2800", value:TRUE);
    set_kb_item(name:"CVE-2005-2872", value:TRUE);
    set_kb_item(name:"CVE-2005-2873", value:TRUE);
    set_kb_item(name:"CVE-2005-3044", value:TRUE);
    set_kb_item(name:"CVE-2005-3053", value:TRUE);
    set_kb_item(name:"CVE-2005-3055", value:TRUE);
    set_kb_item(name:"CVE-2005-3179", value:TRUE);
    set_kb_item(name:"CVE-2005-3180", value:TRUE);
    set_kb_item(name:"CVE-2005-3181", value:TRUE);
    set_kb_item(name:"CVE-2005-3257", value:TRUE);
    set_kb_item(name:"CVE-2005-3271", value:TRUE);
    set_kb_item(name:"CVE-2005-3273", value:TRUE);
    set_kb_item(name:"CVE-2005-3274", value:TRUE);
    set_kb_item(name:"CVE-2005-3275", value:TRUE);
    set_kb_item(name:"CVE-2005-3276", value:TRUE);
  }

  exit(0, "The host is not affected.");
}
