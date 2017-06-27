#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:036
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19245);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2005:036: sudo";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory SUSE-SA:2005:036 (sudo).


Sudo(8) allows the execution of commands as another user and gives the
administrator more flexibility than su(1).
A race condition in the pathname handling of sudo may allow a local user
to execute arbitrary commands. To exploit this bug some conditions need
to be fulfilled. The attacking user needs to be listed in the sudoers file,
he is able to create symbolic links in the filesystem, and a ALL alias-
command needs to follow the attackers entry." );
 script_set_attribute(attribute:"solution", value:
"http://www.suse.de/security/advisories/2005_36_sudo.html" );
 script_set_attribute(attribute:"risk_factor", value:"Medium" );



 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/20");
 script_end_attributes();

 
 summary["english"] = "Check for the version of the sudo package";
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
if ( rpm_check( reference:"sudo-1.6.6-192", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.7p5-120", release:"SUSE9.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.7p5-117.4", release:"SUSE9.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.7p5-118.2", release:"SUSE9.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.8p7-3.2", release:"SUSE9.3") )
{
 security_warning(0);
 exit(0);
}
