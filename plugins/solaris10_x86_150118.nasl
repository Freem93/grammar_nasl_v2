# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2013/09/23.
#

#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(65665);
 script_version("$Revision: 1.7 $");

 script_name(english: "Solaris 10 (x86) : 150118-01");
script_cve_id("CVE-2013-1530");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 150118-01");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10_x86: mac patch.
Date this patch was last updated by Sun : Mar/22/13');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/150118-01");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
 script_set_attribute(attribute: "patch_publication_date", value: "2013/03/22");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/24");
  script_cvs_date("$Date: 2013/09/23 10:58:43 $");
 script_end_attributes();

 script_summary(english: "Check for patch 150118-01");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");




include("solaris.inc");

e +=  solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"150118-01", obsoleted_by:"150401-02 ", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.16.34");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_note(0);
	else  
	   security_note(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
