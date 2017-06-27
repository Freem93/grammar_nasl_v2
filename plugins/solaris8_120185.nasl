# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a recommended security fix.
#
# Disabled on 2011/09/17.

#
# (C) Tenable Network Security, Inc.
#
#

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(23419);
 script_version("$Revision: 1.30 $");

 script_name(english: "Solaris 5.8 (sparc) : 120185-19");
 script_xref(name:"OSVDB", value:"26940");
 script_xref(name:"OSVDB", value:"26941");
 script_xref(name:"OSVDB", value:"26942");
 script_xref(name:"OSVDB", value:"26943");
 script_xref(name:"OSVDB", value:"26944");
 script_xref(name:"OSVDB", value:"26945");
 script_xref(name:"OSVDB", value:"33315");
 script_xref(name:"OSVDB", value:"33971");
 script_xref(name:"OSVDB", value:"33972");
 script_xref(name:"OSVDB", value:"35378");
 script_xref(name:"OSVDB", value:"36509");
 script_xref(name:"OSVDB", value:"40546");
 script_xref(name:"OSVDB", value:"40548");
 script_cve_id("CVE-2006-2198", "CVE-2006-3117", "CVE-2006-5870", "CVE-2007-0002", "CVE-2007-0238", "CVE-2007-0239", "CVE-2007-0245", "CVE-2007-1466", "CVE-2007-2754", "CVE-2007-2834", "CVE-2007-4575");
 script_set_attribute(attribute: "synopsis", value:
"The remote host is missing Sun Security Patch number 120185-19");
 script_set_attribute(attribute: "description", value:
'StarOffice 8 (Solaris): Update 14.
Date this patch was last updated by Sun : Sep/09/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/120185-19");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("$Date: 2011/09/18 01:29:19 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/07/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/30");
 script_end_attributes();

 script_summary(english: "Check for patch 120185-19");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



# Deprecated.
exit(0, "The associated patch is not currently a recommended security fix.");

include("solaris.inc");

e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-base", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-calc", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-core01", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-core02", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-core03", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-core04", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-core05", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-core06", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-core07", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-core08", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-core09", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-de-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-de-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-de", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-draw", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-es-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-es-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-es", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-fr-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-fr-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-fr", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-gnome-integration", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-graphicfilter", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-hu-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-hu-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-hu", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-impress", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-it-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-it-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-it", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-javafilter", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-lngutils", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-math", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-nl-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-nl-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-nl", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-onlineupdate", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-pl-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-pl-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-pl", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-pt-BR-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-pt-BR-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-pt-BR", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-pt-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-pt-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-pt", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-ru-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-ru-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-ru", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-sunsearchtoolbar", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-sv-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-sv-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-sv", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-w4wfilter", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-writer", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.8", arch:"sparc", patch:"120185-19", obsoleted_by:"", package:"SUNWstaroffice-xsltfilter", version:"8.0.0,REV=106.2005.05.26");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
