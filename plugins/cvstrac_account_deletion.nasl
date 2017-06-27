#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14283);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");

 script_osvdb_id(8642);

 script_name(english:"CVSTrac CVSROOT/passwd Arbitrary Account Deletion");
 script_summary(english:"Checks for CVSTrac version");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by an account deletion vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running cvstrac, a web-based bug and 
patch-set tracking system for CVS.

This version of CVSTRAC is vulnerable to a flaw wherein a remote 
attacker can overwrite a critical file, thereby giving them elevated 
access and potentially control over other user accounts.

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of CVSTrac
***** installed there.");
 script_set_attribute(attribute:"see_also", value:"http://www.cvstrac.org/cvstrac/tktview?tn=28");
 script_set_attribute(attribute:"see_also", value:"http://www.cvstrac.org/cvstrac/chngview?cn=136");
 script_set_attribute(attribute:"solution", value:
"Update to version 1.1.4 or later as this reportedly fixes the issue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/17");
 script_set_attribute(attribute:"vuln_publication_date", value:"2002/05/21");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("cvstrac_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/cvstrac" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
version = stuff[1];

if(ereg(pattern:"^(0\..*|1\.0\.[0-5]([^0-9]|$))", string:version))
 		security_warning(port);
