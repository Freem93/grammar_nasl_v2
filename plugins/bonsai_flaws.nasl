#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11440);
 script_cve_id("CVE-2003-0152", "CVE-2003-0153", "CVE-2003-0154", "CVE-2003-0155");
 script_bugtraq_id(5516, 5517);
 script_osvdb_id(
  5457,
  5458,
  5459,
  5460,
  5461,
  5462,
  5463,
  5464,
  5465,
  5634
 );
 script_version ("$Revision: 1.27 $");
		
 script_name(english:"Mozilla Bonsai Mutiple Flaws (Auth Bypass, XSS, Cmd Exec, PD)");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a CGI which is vulnerable to multiple flaws
allowing code execution and cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host has the CGI suite 'Bonsai' installed. 

This suite is used to browse a CVS repository with a web browser. 

The remote version of this software is to be vulnerable to various
flaws ranging from path disclosure and cross-site scripting to remote
command execution. 

An attacker may exploit these flaws to temper with the integrity of
the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Bonsai" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/08/20");
 script_cvs_date("$Date: 2016/11/11 20:08:42 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determine if bonsai is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

dirs = make_list(cgi_dirs());
foreach d (dirs)
{
 url = string(d, "/cvslog.cgi?file=<SCRIPT>window.alert</SCRIPT>");
 r = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(r)) exit(0);
 buf = strcat(r[0], r[1], '\r\n', r[2]);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) &&
    "Rcs file" >< buf &&
     "<SCRIPT>window.alert</SCRIPT>" >< buf)
   {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
}
