#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:069
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(24446);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "SUSE-SA:2006:069: asterisk";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2006:069 (asterisk).


Two security problem have been found and fixed in the PBX software
Asterisk.

CVE-2006-5444: Integer overflow in the get_input function in the
Skinny channel driver (chan_skinny.c) as used by Cisco SCCP phones,
allows remote attackers to potentially execute arbitrary code via a
certain dlen value that passes a signed integer comparison and leads
to a heap-based buffer overflow.

CVE-2006-5445: A vulnerability in the SIP channel driver
(channels/chan_sip.c) in Asterisk on SUSE Linux 10.1 allows remote
attackers to cause a denial of service (resource consumption)
via unspecified vectors that result in the creation of 'a real pvt
structure' that uses more resources than necessary." );
 script_set_attribute(attribute:"solution", value:
"http://www.novell.com/linux/security/advisories/2006_69_asterisk.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the asterisk package";
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
if ( rpm_check( reference:"asterisk-1.0.9-4.6", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"asterisk-1.0.6-4.6", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
