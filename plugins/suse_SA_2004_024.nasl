#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:024
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14231);
 script_bugtraq_id(10852);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2004-0415");
 
 name["english"] = "SUSE-SA:2004:024: kernel";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory 
SUSE-SA:2004:024 (kernel).

This kernel is vulnerable to a race condition in the 64-bit
file offset handling code.

The file offset pointer (f_pos) is changed during reading, writing, and
seeking through a file to point to the current position in a file.
The Linux kernel offers a 32bit and a 64bit API. Unfortunately the
value conversion between this two APIs as well as the access to the f_pos
pointer is defective.

An attacker, exploiting this flaw, would need local access to the 
machine.  Upon successful exploitation, an attacker would be able
to read potentially confidential kernel memory.

Additionally a bug in the implementation of chown(2) for updating inode
times, and a denial-of-service condition that can occur while handling
signals was fixed." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2004_24_kernel.html" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");




 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/09");
 script_cvs_date("$Date: 2010/10/06 02:47:45 $");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the kernel package";
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
if ( rpm_check( reference:"k_deflt-2.4.18-310", release:"SUSE8.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_i386-2.4.18-310", release:"SUSE8.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.18.SuSE-310", release:"SUSE8.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.18-310", release:"SUSE8.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.18-310", release:"SUSE8.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.18-310", release:"SUSE8.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-238", release:"SUSE8.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-238", release:"SUSE8.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-238", release:"SUSE8.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-238", release:"SUSE8.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.21-238", release:"SUSE8.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-238", release:"SUSE8.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-238", release:"SUSE8.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.20-118", release:"SUSE8.2") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.20-118", release:"SUSE8.2") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.20.SuSE-118", release:"SUSE8.2") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.20-118", release:"SUSE8.2") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_psmp-2.4.20-118", release:"SUSE8.2") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.20-118", release:"SUSE8.2") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.20-118", release:"SUSE8.2") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-238", release:"SUSE9.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-238", release:"SUSE9.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_um-2.4.21-238", release:"SUSE9.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp4G-2.4.21-238", release:"SUSE9.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-238", release:"SUSE9.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_smp-2.4.21-238", release:"SUSE9.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_deflt-2.4.21-238", release:"SUSE9.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"k_athlon-2.4.21-238", release:"SUSE9.0") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.5-7.104", release:"SUSE9.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.5-7.104", release:"SUSE9.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.5-7.104", release:"SUSE9.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.5-7.104", release:"SUSE9.1") )
{
 security_note(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.5-7.104", release:"SUSE9.1") )
{
 security_note(0);
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"SUSE8.0")
 || rpm_exists(rpm:"kernel-", release:"SUSE8.1")
 || rpm_exists(rpm:"kernel-", release:"SUSE8.2")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.0")
 || rpm_exists(rpm:"kernel-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0415", value:TRUE);
}
