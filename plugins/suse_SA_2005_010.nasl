#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:010
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17237);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2005:010: kernel";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:010 (kernel).


The previous kernel security update for the SUSE Linux 9.1
and the SUSE Linux Enterprise Server 9 based products caused
problems with the NVidia driver for users with NVidia graphics cards. 

Stricter checking in the memory management functions in the kernel
caused the kernel to hang as soon as the X Window System was started.
This bug happens to all users who installed the NVidia driver via YOU
and therefore still used the 1.0-5336 version of the NVidia driver.

This updates fixes this problem,

Users who don't use the NVidia driver or use a later version of the
driver are not affected and do not need to update.

To install the update on an affected/broken system, boot the SUSE Linux
9.1 system into run level 3 (by supplying '3' as command line argument on
the boot prompt), then log in as root and run the text mode version
of the YaST Online Update.

('yast online_update')

Follow the instructions in the curses interface and install this
kernel update.

No other fixes are included in this update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_10_kernel.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/01");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the kernel package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kernel-bigsmp-2.6.5-7.147", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.5-7.147", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.5-7.147", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.5-7.147", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.5-7.147", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"ltmodem-2.6.2-38.13", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"kernel-docs-2.6.5-7.147", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
