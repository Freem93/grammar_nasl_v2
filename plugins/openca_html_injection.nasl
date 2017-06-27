#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(14700);
  script_version ("$Revision: 1.14 $"); 
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2004-0787");
  script_bugtraq_id(11113);
  script_osvdb_id(9749);

  script_name(english:"OpenCA Client System Browser Form Input Field XSS");
  script_summary(english:"Checks for the version of OpenCA");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a cross-site
scripting vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host seems to be running an older version of OpenCA. 

It is reported that OpenCA versions up to and including 0.9.2-RC2 are
affected by an HTML injection vulnerability when processing user input
to the web form frontend.  This issue may permit an attacker to
execute hostile HTML code in the security context of the affected
application." );
  script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/09");
  script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/06");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");

  script_family(english:"CGI abuses : XSS");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

host = get_host_name();
port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

res = http_send_recv3(method:"GET", item:"/cgi-bin/pub/pki?cmd=serverInfo", port:port);
if (isnull(res)) exit(1,"Null response to /cgi-bin/pub/pki request.");

str = egrep(pattern:"Server Information for OpenCA Server Version .*", string:res[2]);
if ( str )
{
  version = ereg_replace(pattern:".*Server Information for OpenCA Server Version (.*)\)", string:str, replace:"\1");
  set_kb_item(name:"www/" + port + "/openca/version", value:version);
}

if (egrep(pattern:"Server Information for OpenCA Server Version 0\.([0-8][^0-9]|9\.[0-2][^0-9])", string:str)) 
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  security_warning(port);
}
