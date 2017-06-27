#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15564);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");

 script_cve_id("CVE-2004-0798");
 script_bugtraq_id(11043);
 script_osvdb_id(9177);

 script_name(english:"Ipswitch WhatsUp Gold _maincfgret.cgi Remote Overflow");
 script_summary(english:"Checks for the presence of /_maincfgret.cgi");

 script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has a buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The '_maincfgret' CGI is installed on the remote web server. Some
versions are vulnerable to a buffer overflow. Note that Nessus only
checked for the presence of this CGI, and did not attempt to determine
whether or not it is vulnerable.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10d9bfab");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Oct/32");
 script_set_attribute(attribute:"solution", value:"Upgrade to WhatsUp Gold 8.03 HF 1 if necessary.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Ipswitch WhatsUp Gold 8.03 Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/25");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
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

if (is_cgi_installed3(item: "/_maincfgret.cgi", port:port))
{
  security_hole(port);
  exit(0);
}

if (is_cgi_installed3(item:"_maincfgret.cgi", port:port))
 security_hole(port);
