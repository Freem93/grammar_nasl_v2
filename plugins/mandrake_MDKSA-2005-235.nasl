#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:235. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20466);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/31 23:51:58 $");

  script_cve_id("CVE-2005-2490", "CVE-2005-2492", "CVE-2005-2873", "CVE-2005-3044", "CVE-2005-3055", "CVE-2005-3179", "CVE-2005-3180", "CVE-2005-3181", "CVE-2005-3257", "CVE-2005-3274");
  script_xref(name:"MDKSA", value:"2005:235");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2005:235)");
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
"Multiple vulnerabilities in the Linux 2.6 kernel have been discovered
and corrected in this update :

A stack-based buffer overflow in the sendmsg function call in versions
prior to 2.6.13.1 allow local users to execute arbitrary code by
calling sendmsg and modifying the message contents in another thread
(CVE-2005-2490).

The raw_sendmsg function in versions prior to 2.6.13.1 allow local
users to cause a DoS (change hardware state) or read from arbitrary
memory via crafted input (CVE-2005-2492).

The ipt_recent module in versions prior to 2.6.12 does not properly
perform certain tests when the jiffies value is greater than LONG_MAX,
which can cause ipt_recent netfilter rules to block too early
(CVE-2005-2873).

Multiple vulnerabilities in versions prior to 2.6.13.2 allow local
users to cause a DoS (oops from null dereference) via fput in a 32bit
ioctl on 64-bit x86 systems or sockfd_put in the 32-bit routing_ioctl
function on 64-bit systems (CVE-2005-3044).

Versions 2.6.8 to 2.6.14-rc2 allow local users to cause a DoS (oops)
via a userspace process that issues a USB Request Block (URB) to a USB
device and terminates before the URB is finished, which leads to a
stale pointer reference (CVE-2005-3055).

drm.c in version 2.6.13 and earlier creates a debug file in sysfs with
world-readable and world-writable permissions, allowing local users to
enable DRM debugging and obtain sensitive information (CVE-2005-3179).

The Orinoco driver in 2.6.13 and earlier does not properly clear
memory from a previously used packet whose length is increased,
allowing remote attackers to obtain sensitive information
(CVE-2005-3180).

Kernels 2.6.13 and earlier, when CONFIG_AUDITSYSCALL is enabled, use
an incorrect function to free names_cache memory, preventing the
memory from being tracked by AUDITSYSCALL code and leading to a memory
leak (CVE-2005-3181).

The VT implementation in version 2.6.12 allows local users to use
certain IOCTLs on terminals of other users and gain privileges
(CVE-2005-3257).

A race condition in ip_vs_conn_flush in versions prior to 2.6.13, when
running on SMP systems, allows local users to cause a DoS (null
dereference) by causing a connection timer to expire while the
connection table is being flushed before the appropriate lock is
acquired (CVE-2005-3274).

The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels.

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.12.14mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i586-up-1GB-2.6.12.14mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i686-up-4GB-2.6.12.14mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.6.12.14mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xbox-2.6.12.14mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xen0-2.6.12.14mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xenU-2.6.12.14mdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"kernel-2.6.12.14mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-i586-up-1GB-2.6.12.14mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-i686-up-4GB-2.6.12.14mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-smp-2.6.12.14mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-source-2.6-2.6.12-14mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-source-stripped-2.6-2.6.12-14mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-xbox-2.6.12.14mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-xen0-2.6.12.14mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-xenU-2.6.12.14mdk-1-1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
