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
 script_id(23617);
 script_version("$Revision: 1.29 $");

 script_name(english: "Solaris 5.9 (x86) : 120190-19");
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
"The remote host is missing Sun Security Patch number 120190-19");
 script_set_attribute(attribute: "description", value:
'StarSuite 8 (Solaris_x86): Update 14.
Date this patch was last updated by Sun : Sep/11/09');
 script_set_attribute(attribute: "solution", value:
"You should install this patch for your system to be up-to-date.");
 script_set_attribute(attribute: "see_also", value:
"https://getupdates.oracle.com/readme/120190-19");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/06");
 script_cvs_date("$Date: 2011/09/18 01:40:37 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/07/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/30");
 script_end_attributes();

 script_summary(english: "Check for patch 120190-19");
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

e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-base", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-calc", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-core01", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-core02", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-core03", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-core04", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-core05", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-core06", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-core07", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-core08", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-core09", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-draw", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-gnome-integration", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-graphicfilter", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-impress", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-ja-fonts", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-ja-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-ja-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-ja", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-javafilter", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-ko-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-ko-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-ko", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-lngutils", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-math", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-onlineupdate", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-sunsearchtoolbar", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-writer", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-xsltfilter", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-zh-CN-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-zh-CN-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-zh-CN", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-zh-TW-help", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-zh-TW-res", version:"8.0.0,REV=106.2005.05.26");
e +=  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"120190-19", obsoleted_by:"", package:"SUNWstarsuite-zh-TW", version:"8.0.0,REV=106.2005.05.26");
if ( e < 0 ) { 
	if ( NASL_LEVEL < 3000 ) 
	   security_hole(0);
	else  
	   security_hole(port:0, extra:solaris_get_report());
	exit(0); 
} 
exit(0, "Host is not affected");
