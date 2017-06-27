#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(16000);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2004-1146");
 script_bugtraq_id(12017);
 script_osvdb_id(12683, 12684);
 script_xref(name:"Secunia", value:"13675");

 script_name(english:"CVSTrac < 1.1.5 Multiple XSS");
 script_summary(english:"Checks for CVSTrac version");

 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has multiple cross-site
scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running CVSTrac, a web-based bug and
patch-set tracking system for CVS.

According to its version number, the remote installation of CVSTrac
has multiple cross-site scripting flaws.  A remote attacker could
exploit this by tricking a user into requesting a malicious URL, which
would result in the execution of arbitrary script code as that user." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.cvstrac.org/cvstrac/chngview?cn=320"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.cvstrac.org/cvstrac/chngview?cn=321"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to CVSTrac 1.1.5 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/17");
 script_cvs_date("$Date: 2015/01/13 20:37:05 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_dependencie("cvstrac_detect.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/cvstrac" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
version = stuff[1];

if(ereg(pattern:"^(0\..*|1\.0\.|1\.1\.[0-4]([^0-9]|$))", string:version))
{
 		security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

