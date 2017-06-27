#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33548);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/10/27 15:03:53 $");

  script_cve_id("CVE-2008-1663");
  script_bugtraq_id(30029);
  script_osvdb_id(46659);
  script_xref(name:"Secunia", value:"30912");

  script_name(english:"HP System Management Homepage < 2.1.12 Unspecified XSS");
  script_summary(english:"Checks version of HP SMH");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running HP System Management Homepage
(SMH), a web-based management interface for ProLiant and Integrity
servers.

The version of HP SMH installed on the remote host fails to sanitize
user input to an unspecified parameter and script before using it to
generate dynamic HTML.  A remote attacker may be able to exploit this
issue to cause arbitrary HTML and script code to be executed by a
user's browser in the context of the affected website.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/14919");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jul/8");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP System Management Homepage 2.1.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("compaq_wbem_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/hp_smh");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:2381, embedded:TRUE);


install = get_install_from_kb(appname:'hp_smh', port:port, exit_on_fail:TRUE);
prod = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");


# nb: HP only says Linux and Windows are affected - no mention of HP-UX.
os = get_kb_item("Host/OS");
if (!os || ("Windows" >!< os && "Linux" >!< os)) exit(0);


dir = install['dir'];
version = install['ver'];
if (version == UNKNOWN_VER)
  exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' is unknown.');


# Versions 2.1.10 and 2.1.11 are affected.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 2 && ver[1] == 1 && (ver[2] == 10 || ver[2] == 11))
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    version = string(ver[0], ".", ver[1], ".", ver[2]);
    source_line = get_kb_item("www/"+port+"/hp_smh/source");

    report = '\n  Product           : ' + prod;
    if (!isnull(source_line))
      report += '\n  Version source    : ' + source_line;
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.1.12\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else exit(0, prod+" "+version+" is listening on port "+port+" and is not affected.");
