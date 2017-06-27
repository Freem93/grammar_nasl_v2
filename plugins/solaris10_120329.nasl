# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2013/04/30.
#

#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(20943);
 script_version("$Revision: 1.22 $");

 script_name(english: "Solaris 10 (sparc) : 120329-02");
 script_osvdb_id(23227);
script_cve_id("CVE-2006-0769");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120329-02");
 script_set_attribute(attribute: "description", value:
'SunOS 5.10: rexec patch.
Date this patch was last updated by Sun : Feb/13/06');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"http://download.oracle.com/sunalerts/1000978.1.html");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute: "patch_publication_date", value: "2006/02/13");
 script_set_attribute(attribute: "cpe", value: "cpe:/o:sun:solaris");
 script_set_attribute(attribute: "plugin_type", value: "local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/19");
  script_cvs_date("$Date: 2013/04/30 10:42:30 $");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/14");
 script_end_attributes();

 script_summary(english: "Check for patch 120329-02");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");




include("solaris.inc");

e +=  solaris_check_patch(release:"5.10", arch:"sparc", patch:"120329-02", obsoleted_by:"148975-01 ", package:"SUNWrcmds", version:"11.10.0,REV=2005.01.21.15.53");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
