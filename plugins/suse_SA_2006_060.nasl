#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:060
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24438);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:060: clamav";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:060 (clamav).


Two security problems have been found and fixed in the anti virus
scan engine 'clamav', which could be used by remote attackers
sending prepared E-Mails containing special crafted infected files
to potentially execute code.

CVE-2006-4182: A problem in dealing with PE (Portable Executables aka
Windows .EXE) files could result in an integer overflow, causing a heap
overflow, which could be used by attackers to potentially execute code.

CVE-2006-5295: A problem in dealing with CHM (compressed help file)
exists that could cause an invalid memory read, causing the clamav
engine to crash." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_60_clamav.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the clamav package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"clamav-0.88.5-0.1", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-0.88.5-0.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-0.88.5-0.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
