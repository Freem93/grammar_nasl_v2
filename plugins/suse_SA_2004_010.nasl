#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2004:010
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13828);
 script_bugtraq_id(10211, 10221, 10233);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2004-0228", "CVE-2004-0229", "CVE-2004-0394", "CVE-2004-0424", "CVE-2004-0427");
 
 name["english"] = "SuSE-SA:2004:010: Linux Kernel";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SuSE-SA:2004:010 (Linux Kernel).


Various vulnerabilities have been fixed in the newly available kernel
updates. The updates consist of fixes for the following vulnerabilities:

- The do_fork() memory leak, which could lead to a local DoS attack.
All kernels except for SLES7 are affected.
- The setsockopt() MCAST buffer overflow which allows local attackers
to execute arbitrary code with root privileges. Only SLES8 based
products and SL 8.1 and SL 9.0 kernels are affected by this bug.
- The misuse of the fb_copy_cmap() function which could also allow
local attackers to execute arbitrary code with root privileges.
Only the SL 9.1 kernel is affected.
- The integer overflow in the cpufreq_procctl() function.
Only the SL 9.1 kernel is affected.
- The wrong permissions on /proc/scsi/qla2300/HbaApiNode which allow
local attackers to start DoS attacks. SLES8 kernels and SL 8.1 and
9.0 kernels are affected.
- A buffer overflow in panic(). Although there seems no way to trigger
this bug, it has been fixed.

If you use a maintained product or SuSE Linux 8.1 or 9.0, we recommend
an update. If you offer shell access to users we recommend an update in
any case." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_10_kernel.html" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the Linux Kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"k_deflt-2.4.18-293", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.18-293", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.18-293", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_i386-2.4.18-293", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-215", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-215", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-215", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.21-215", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.20-111", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.20-111", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.20-111", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.20-111", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-215", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-215", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-215", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.4-54.3", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.4-54.3", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.4-54.3", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.4-54.3", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"Linux Kernel-", release:"SUSE8.0")
 || rpm_exists(rpm:"Linux Kernel-", release:"SUSE8.1")
 || rpm_exists(rpm:"Linux Kernel-", release:"SUSE8.2")
 || rpm_exists(rpm:"Linux Kernel-", release:"SUSE9.0")
 || rpm_exists(rpm:"Linux Kernel-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0228", value:TRUE);
 set_kb_item(name:"CVE-2004-0229", value:TRUE);
 set_kb_item(name:"CVE-2004-0394", value:TRUE);
 set_kb_item(name:"CVE-2004-0424", value:TRUE);
 set_kb_item(name:"CVE-2004-0427", value:TRUE);
}
