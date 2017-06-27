#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16064);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");

 script_cve_id("CVE-2004-1373");
 script_bugtraq_id(12096);
 script_osvdb_id(12585);

 script_name(english:"SHOUTcast Server Filename Handling Format String");
 script_summary(english:"SHOUTcast version check");

 script_set_attribute(attribute:"synopsis", value:
"The remote streaming audio server is vulnerable to a format string
attack.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of SHOUTcast Server installed on
the remote host is earlier than 1.9.5.  Such versions fail to validate
requests containing format string specifiers before using them in a call
to 'sprintf()'.  An unauthenticated, remote attacker may be able to
exploit this issue to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Dec/363");
 script_set_attribute(attribute:"solution", value:"Upgrade to SHOUTcast 1.9.5 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'SHOUTcast DNAS/win32 1.9.4 File Request Format String Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/28");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:shoutcast_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

req = 'GET /content/' + rand_str(length:10) + '.mp3 HTTP/1.0\r\n\r\n';

port = get_http_port(default: 8000);

w = http_send_recv_buf(port:port, data:req);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
banner = strcat(w[0], w[1], '\r\n', w[2]);

if (egrep(pattern:"SHOUTcast Distributed Network Audio Server.*v(0\.|1\.[0-8]\.|1\.9\.[0-4][^0-9])", string:banner) )
  {
   security_hole(port);
   exit(0);
  }
