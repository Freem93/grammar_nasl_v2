#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SuSE-SA:2003:051
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13819);
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "SuSE-SA:2003:051: lftp";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SuSE-SA:2003:051 (lftp).


The the flexible and powerful FTP command-line client  lftp is vulnerable
to two remote buffer overflows.
When using lftp via HTTP or HTTPS to execute commands like 'ls' or 'rels'
specially prepared directories on the server can trigger a buffer overflow
in the HTTP handling functions of lftp to possibly execute arbitrary code
on the client-side.
Please note, to exploit these bugs an attacker has to control the server-
side of the context and the attacker will only gain access to the account
of the user that is executing lftp.

There is no temporary workaround known.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/2003_051_lftp.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/25");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the lftp package";
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
if ( rpm_check( reference:"lftp-2.6.4-44", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"lftp-2.6.6-71", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
