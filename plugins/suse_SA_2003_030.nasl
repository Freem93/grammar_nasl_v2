#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:030
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13799);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "SUSE-SA:2003:030: radiusd-cistron";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2003:030 (radiusd-cistron).


The package radiusd-cistron is an implementation of the RADIUS protocol.
Unfortunately the RADIUS server handles too large NAS numbers not
correctly. This leads to overwriting internal memory of the server
process and may be abused to gain remote access to the system the RADIUS
server is running on.

There is no temporary workaround known.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_030_radiusd_cistron.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the radiusd-cistron package";
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
if ( rpm_check( reference:"radiusd-cistron-1.6.6-88", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"radiusd-cistron-1.6.4-182", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"radiusd-cistron-1.6.4-182", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
