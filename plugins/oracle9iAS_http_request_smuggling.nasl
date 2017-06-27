#
# (C) Tenable Network Security, Inc.

#

include('compat.inc');

if (description)
{
  script_id(17708);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2005-2093");
  script_bugtraq_id(16287);
  script_osvdb_id(43448);

  script_name(english:"Oracle 9i Application Server HTTP Request Smuggling");
  script_summary(english:"Checks for Oracle Application Server 9i");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by a cross-site scripting
vulnerability.");

  script_set_attribute(attribute:"description", value:
"The version of Oracle Application Server installed on the remote host
allows attackers to poison the web cache, bypass web application
firewall protection, and conduct cross-site scripting attacks via an
HTTP request with both a 'Transfer-Encoding: chunked' header and a
'Content-Length' header.");

  script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/securityreviews/5GP0220G0U.html");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server");
  script_end_attributes();
  
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Only PCI considers this an issue.
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

port = get_http_port(default:80);

# Check if we are looking Oracle Application Servers
banner = get_http_banner(port:port, exit_on_fail:TRUE);
if ("Server: Oracle-Application-Server" >!< banner) exit(0, "The web server listening on port "+port+" is not Oracle Application Server.");

source = egrep(pattern:'^Server: Oracle-Application-Server.*', string:banner);
if (isnull(source)) exit(1, 'Couldn\'t extract the Server response header from the Oracle Application Server listening on port '+port+'.');

matches = eregmatch(pattern:'^Server: Oracle-Application-Server-9i/([0-9\\.]+)', string:source);
if (isnull(matches)) exit(1, 'Couldn\'t determine the version number of Oracle Application Server listening on port '+port+'.');
version = matches[1];

if (version =~ '^9\\.0\\.2[^0-9]')
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, 'The Oracle Application Server version '+version+' install listening on port '+port+' is not affected.');
