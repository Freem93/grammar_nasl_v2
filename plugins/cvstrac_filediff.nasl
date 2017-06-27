#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14220);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/10/10 15:57:04 $");

 script_cve_id("CVE-2004-1456");
 script_bugtraq_id(10878);
 script_osvdb_id(8373);

 script_name(english:"CVSTrac filediff Arbitrary Remote Code Execution");
 script_summary(english:"Checks for CVSTrac version");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a cGI application that is affected
by a remote code execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running cvstrac, a web-based bug and 
patch-set tracking system for CVS.

This version of filediff has a flaw in the input sanitation which, 
when exploited, can lead to a remote attacker executing arbitrary
commands on the system.

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of CVSTrac
***** installed there.");
 script_set_attribute(attribute:"see_also", value:"http://www.cvstrac.org/cvstrac/chngview?cn=316");
 script_set_attribute(attribute:"see_also", value:"http://www.cvstrac.org/cvstrac/tktview?tn=339");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Aug/62");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Aug/89");
 script_set_attribute(attribute:"solution", value:
"Update to version 1.1.4 or later as this reportedly fixes the issue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/09");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/05");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("cvstrac_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);
kb = get_kb_item("www/" + port + "/cvstrac" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
version = stuff[1];
if(ereg(pattern:"^(0\.|1\.(0|1\.[0-3]([^0-9]|$)))", string:version))
	security_hole(port);
