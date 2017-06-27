#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(15570);
 script_version("$Revision: 1.11 $");
 script_bugtraq_id(11529);
 script_osvdb_id(53009);

 script_name(english:"PostNuke Trojaned Distribution");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands can be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running a copy of a trojaned version of the
'PostNuke' content management system.

PostNuke is a content management system in PHP whose main website has
been compromised between the 24th and 26th of October 2004. An attacker
modified some of the source code of the tool to execute arbitrary 
commands remotely on the remote host, by passing arguments to the 'oops'
parameter of the file pnAPI.php." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of PostNuke." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/26");
 script_cvs_date("$Date: 2014/07/11 19:38:17 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:postnuke_software_foundation:postnuke");
 script_end_attributes();

 script_summary(english:"Determines if PostNuke is trojaned");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Backdoors");
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_dependencie("postnuke_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/postnuke");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/postnuke" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
dir = stuff[2];
if(!can_host_php(port:port))exit(0);

u = string(dir, "/includes/pnAPI.php?oops=id");
r = http_send_recv3(port: port, item: u, method: "GET");
if (isnull(r)) exit(0);
res = r[0]+r[1]+'\r\n'+r[2];
if (egrep(pattern:"uid=[0-9].*gid=[0-9]", string:res) ) 
  security_hole(port, extra: strcat('\nThe id command could be run through the following URL :\n\n', build_url(port: port, qs: u), '\n'));
