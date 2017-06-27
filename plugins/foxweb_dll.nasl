#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11939);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");

 script_cve_id("CVE-2003-0762");
 script_bugtraq_id(8547);
 script_osvdb_id(11740, 11741);

 script_name(english:"Foxweb foxweb.exe / foxweb.dll Long URL Remote Overflow");
 script_summary(english:"Checks for the presence of foxweb.exe or foxweb.dll");

 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is prone to buffer
overflow attacks.");
 script_set_attribute(attribute:"description", value:
"The foxweb.dll or foxweb.exe CGI is installed.

Versions 2.5 and below of this CGI program have a remote stack buffer
overflow. A remote attacker could use this to crash the web server, or
possibly execute arbitrary code.

** Since Nessus just verified the presence of the CGI but could ** not
check the version number, this might be a false alarm.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2003/q3/95");
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/12/04");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

l = make_list("foxweb.dll", "foxweb.exe");
foreach cgi (l)
{
  res = is_cgi_installed3(item:cgi, port:port);
  if(res)
  {
    security_hole(port);
    exit(0);	# As we might fork, we exit here
  }
}
