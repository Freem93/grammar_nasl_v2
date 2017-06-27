#
# written by K-Otik.com <ReYn0@k-otik.com>
#
# Basit cms Cross Site Scripting Bugs
#
#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <mailto:ertank@olympos.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns
#

# Changes by Tenable:
# - Avoid FPs - Check for 200 in status line and XSS in body (10/20/2011)

include("compat.inc");

if (description)
{
 script_id(11445);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_bugtraq_id(7139);
 script_osvdb_id(50538, 50539, 50540);

 script_name(english:"Basit CMS Multiple Script XSS");
 script_summary(english:"Determine if Basit cms is vulnerable to xss attack");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by
several issues.");
 script_set_attribute(attribute:"description", value:
"Basit cms 1.0 has a cross-site scripting bug. An attacker may use it
to perform a cross-site scripting attack on this host.

In addition to this, it is vulnerable to a SQL insertion attack that
could allow an attacker to get the control of your database.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Mar/265");
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/23");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2016 k-otik.com");

 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP", "Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0, "Port "+port+" is closed.");
if(!can_host_php(port:port))
 exit(0, "The web server on port "+port+" does not support PHP scripts.");

if(get_kb_item(string("www/", port, "/generic_xss")))
 exit(0, "The web server on port "+port+" is vulnerable to XSS.");

dir = make_list(cgi_dirs());


foreach d (dir)
{
 url = string(d, "/modules/Submit/index.php?op=pre&title=<script>window.alert(document.cookie);</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL ) exit(0);

 buf = split(buf, sep:'\r\n\r\n', keep:FALSE);
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] +200 ", string:buf[0]) &&
    "<script>window.alert(document.cookie);</script>" >< buf[1])
   {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
}

