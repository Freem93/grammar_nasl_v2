#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(46885);
 script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2016/10/19 14:14:42 $");

 script_cve_id("CVE-2008-5519");
 script_bugtraq_id(34412);
 script_osvdb_id(53381);
 script_xref(name:"Secunia", value:"34621");
 
 script_name(english:"Apache Tomcat JK Connector Content-Length Header Cross-User Information Disclosure");
 script_summary(english:"Checks for version of mod_jk.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to an information disclosure attack.");
 script_set_attribute(attribute:"description",  value:
"Based on the Server response header, the installation of the JK
Connector (mod_jk) in Apache Tomcat listening on the remote host is
version 1.2.x prior to 1.2.27. It is, therefore, affected by an
information disclosure vulnerability. A remote attacker can view the
response associated with a different user's request, either by sending
a request with a Content-Length without data or by sending repeated
requests very quickly. 

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/502530");
 script_set_attribute(attribute:"solution", value:"Upgrade to mod_jk version 1.2.27 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(200);

 script_set_attribute(attribute:"vuln_publication_date", value: "2009/04/07");
 script_set_attribute(attribute:"patch_publication_date",value:"2009/04/07");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/06/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat_connectors");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (!isnull(banner)) exit(0, "Failed to retrieve the banner from the web server on port " + port + ".");

if ("Server: " >!< banner) exit(0, "The banner from the web server on port " + port + " does not have a Server response header.");
if ("mod_jk" >!< banner) exit(0, "The banner from the web server on port " + port + " does not mention 'mod_jk'.");

foreach line (split(banner, keep:FALSE))
  if ("Server: " >< line)
  {
    serv = line - 'Server: ';
    break;
  }

matches = eregmatch(pattern: 'mod_jk/([0-9.]+[A-Za-z0-9.-]*)', string: serv);
if (isnull(matches)) exit(0, "Failed to determine the version of mod_jk listening on port "+port+".");

version = tolower(matches[1]);
if (
  version =~ "^1\.2(\.2[0-6]([a-z]+|-[a-z0-9.-]*|$)|\.1[0-9]([a-z]+|-[a-z0-9.-]*|$)|\.[0-9]([a-z]+|-[a-z0-9.-]*|$)|([a-z]+|-[a-z0-9.-]*|$))" ||
  version =~ "^1\.2\.27-(beta|dev)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n    Server response header : ' + serv  +
      '\n    Installed version      : ' + version +
      '\n    Fixed version          : 1.2.27\n';
    security_note(port: port, extra: report);
  }
  else security_note(port);
  exit(0);
}
else exit(0, "mod_jk version " + version + " is listening on port " + port + " and is not vulnerable.");
