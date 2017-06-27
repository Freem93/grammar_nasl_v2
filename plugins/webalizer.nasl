#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#

# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin family (12/19/2008)
# - Revised plugin title (12/19/2008)
# - Revised description (12/19/2008)
# - Revised plugin title (6/2/2009)

include("compat.inc");

if(description)
{
 script_id(10816); 
 script_version("$Revision: 1.21 $");
 script_cve_id("CVE-2001-0835");
 script_bugtraq_id(3473);
 script_osvdb_id(682, 3868);

 script_name(english:"Webalizer < 2.01-09 Multiple XSS");
  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has multiple cross-site
scripting vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Webalizer, a web server log analysis application, was detected on the
remote host.  This version of Webalizer has multiple cross-site
scripting vulnerabilities that could allow malicious HTML tags to be
injected in the reports."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2001/Oct/223"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Version 2.01-09 and change the directory in 'OutputDir'."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/12/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/10/24");
 script_cvs_date("$Date: 2016/11/15 19:41:08 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

 script_summary(english:"Checks for the Webalizer version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2016 Alert4Web.com");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


dir[0] = "/usage/";	#Standard directory
dir[1] = "/webalizer/";	#Popular directory

port = get_http_port(default:80);


if (get_port_state(port))
{
 for (i = 0; dir[i] ; i = i + 1)
 {
  req = http_get(item:dir[i], port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if ("Generated by The Webalizer" >< buf)
   {
    if (egrep(pattern:"Generated by The Webalizer  Ver(\.|sion) ([01]\.|2\.00|2\.01( |\-0[0-6]))", string:buf))
    {
     security_warning(port:port);
     set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    }
    exit(0);
   }
 }
}
