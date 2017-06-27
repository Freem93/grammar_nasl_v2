#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(27296);
 script_cve_id("CVE-2007-2242", "CVE-2007-2453", "CVE-2007-2876", "CVE-2007-3105", "CVE-2007-3107", "CVE-2007-2525", "CVE-2007-3513", "CVE-2007-3851");

 script_version ("$Revision: 1.9 $");

 name["english"] = "SuSE Security Update: Kernel Update for SUSE Linux 10.1 (kernel-4193)";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SuSE system is missing the security patch kernel-4193." );
 script_set_attribute(attribute:"description", value:
"This kernel update brings the kernel to the one shipped
with SLES 10 Service Pack 1 and also fixes the following
security problems:

- CVE-2007-2242: The IPv6 protocol allows remote attackers
  to cause a denial of service via crafted IPv6 type 0
  route headers (IPV6_RTHDR_TYPE_0) that create network
  amplification between two routers. 

  The default is that RH0 is disabled now. To adjust this,
write to the file /proc/net/accept_source_route6.

- CVE-2007-2453: The random number feature in the Linux
  kernel 2.6 (1) did not properly seed pools when there is
  no entropy, or (2) used an incorrect cast when extracting
  entropy, which might have caused the random number
  generator to provide the same values after reboots on
  systems without an entropy source.

- CVE-2007-2876: A NULL pointer dereference in SCTP
  connection tracking could be caused by a remote attacker
  by sending specially crafted packets. Note that this
  requires SCTP set-up and active to be exploitable.

- CVE-2007-3105: Stack-based buffer overflow in the random
  number generator (RNG) implementation in the Linux kernel
  before 2.6.22 might allow local root users to cause a
  denial of service or gain privileges by setting the
  default wakeup threshold to a value greater than the
  output pool size, which triggers writing random numbers
  to the stack by the pool transfer function involving
  'bound check ordering'.

  Since this value can only be changed by a root user,
exploitability is low.

- CVE-2007-3107: The signal handling in the Linux kernel,
  when run on PowerPC systems using HTX, allows local users
  to cause a denial of service via unspecified vectors
  involving floating point corruption and concurrency.

- CVE-2007-2525: Memory leak in the PPP over Ethernet
  (PPPoE) socket implementation in the Linux kernel allowed
  local users to cause a denial of service (memory
  consumption) by creating a socket using connect, and
  releasing it before the PPPIOCGCHAN ioctl is initialized.

- CVE-2007-3513: The lcd_write function in
  drivers/usb/misc/usblcd.c in the Linux kernel did not
  limit the amount of memory used by a caller, which
  allowed local users to cause a denial of service (memory
  consumption).

- CVE-2007-3851: On machines with a Intel i965 based
  graphics card local users with access to the direct
  rendering devicenode could overwrite memory on the
  machine and so gain root privileges.

This kernel is not compatible to the previous SUSE Linux
10.1 kernel, so the Kernel Module Packages will need to be
updated." );
 script_set_attribute(attribute:"solution", value:
"Install the security patch kernel-4193." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cwe_id(119, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/17");
 script_cvs_date("$Date: 2016/12/22 20:32:46 $");
 script_end_attributes();

 
 summary["english"] = "Checks for the kernel-4193 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-bigsmp-2.6.16.53-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.53-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.53-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-iseries64-2.6.16.53-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.53-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.16.53-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.53-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.53-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.53-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-um-2.6.16.53-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.53-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.53-0.8", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kexec-tools-1.101-32.42", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mkinitrd-1.2-106.58", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"multipath-tools-0.4.6-25.21", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"open-iscsi-2.0.707-0.25", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"udev-085-30.40", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
