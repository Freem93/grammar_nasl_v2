# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2013/02/18.
#

#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(43888);
 script_version("$Revision: 1.10 $");

 script_name(english: "Solaris 10 (x86) : 124445-01");
 script_osvdb_id(40814);
script_cve_id("CVE-2007-5462");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 124445-01");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: mountd patch.
Date this patch was last updated by Sun : Nov/03/06');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1000452.1.html");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20);
 script_set_attribute(attribute: "patch_publication_date", value: "2006/11/03");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/14");
  script_cvs_date("$Date: 2013/02/18 11:56:09 $");
 script_end_attributes();

 script_summary(english: "Check for patch 124445-01");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");




include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"124445-01", obsoleted_by:"148384-01 ", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.16.34");
e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"124445-01", obsoleted_by:"148384-01 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.16.34");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
