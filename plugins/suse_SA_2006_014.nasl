#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:014
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(21093);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2006:014: gpg";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:014 (gpg).


The GNU Privacy Guard (GPG) allows crafting a message which could
check out correct using '--verify', but would extract a different,
potentially malicious content when using '-o --batch'.

The reason for this is that a .gpg or .asc file can contain multiple
plain text and signature streams and the handling of these streams was
only possible when correctly following the gpg state.

The gpg '--verify' option has been changed to be way more strict than
before and fail on files with multiple signatures/blocks to mitigate
the problem of doing the common --verify checks and -o extraction.

This problem could be used by an attacker to remotely execute code
by using handcrafted YaST Online Patch files put onto a compromised
YOU mirror server and waiting for the user to run YOU.

This problem is tracked by the Mitre CVE ID CVE-2006-0049.

This is a different issue than the gpg signature checking problem for" );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2006_14_gpg.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/17");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the gpg package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2010 Tenable Network Security, Inc.");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gpg-1.4.2-5.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gpg-1.2.4-68.13", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gpg-1.2.5-3.6", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gpg-1.4.0-4.4", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
