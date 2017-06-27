#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(13840);
 script_version("$Revision: 1.28 $");

 script_cve_id("CVE-2004-0730", "CVE-2004-2054", "CVE-2004-2055");
 script_bugtraq_id(
   10738, 
   10753, 
   10754, 
   10883
 );
 script_osvdb_id(
   7947, 
   7948, 
   8164, 
   59231, 
   59232
 );

 script_name(english:"phpBB < 2.0.10 Multiple XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to cross-site scripting." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpBB older than 2.0.10.

phpBB contains a flaw that allows a remote cross-site scripting attack. 
This flaw exists because the application does not validate user-supplied 
input in the 'search_author' parameter.

This version is also vulnerable to an HTTP response splitting attack
that permits the injection of CRLF characters in the HTTP headers." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 2.0.10 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/13");
 script_cvs_date("$Date: 2016/05/16 14:22:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpbb_group:phpbb");
script_end_attributes();

 
 script_summary(english:"Check for phpBB version");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 
 script_family(english:"CGI abuses : XSS");
 script_dependencie("phpbb_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/phpBB");
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = matches[1];
if ( ereg(pattern:"^([01]\.|2\.0\.[0-9]([^0-9]|$))", string:version) )
{
	security_warning ( port );
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
