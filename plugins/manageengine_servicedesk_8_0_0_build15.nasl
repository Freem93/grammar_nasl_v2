#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57371);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/08/24 14:43:50 $");

  script_bugtraq_id(49291);
  script_osvdb_id(74713, 74714, 74715, 74716, 74717);
  script_xref(name:"EDB-ID", value:"74720");

  script_name(english:"ManageEngine ServiceDesk Plus 8.0.0 < Build 8015 Multiple XSS Vulnerabilities");
  script_summary(english:"Checks version of ManageEngine ServiceDesk Plus");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that may be affected by
several cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host contains ManageEngine ServiceDesk Plus version 8.0.0
prior to build 8015.  It is thus potentially affected by multiple
cross-site scripting vulnerabilities.  The following pages do not
properly sanitize input to the following scripts and parameters :

  - Page       : 'AddSolution.do'
    Parameters : 'comments' and 'keywords'

  - Page       : 'AnnounceShow.do'
    Parameter  : 'select'

  - Pages      : 'AddNewProblem.cc', 'ChangeDetails.cc'
                 and 'Problems.cc'
    Parameter  : 'reqName'

  - Page       : 'calendar/MiniCalendar.jsp'
    Parameter  : 'module'

  - Pages      : 'HomePage.do' and 'jsp/ServiceCatalog.jsp'
    Parameter  : 'serviceID'

  - Page       : 'WorkOrder.do'
    Parameters : 'attach', 'category', 'description',
                 'level', 'reqName' and 'title'.");

  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Aug/221");
  script_set_attribute(attribute:"see_also", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5039.php");
  # https://www.manageengine.com/products/service-desk/readme-version-8.0.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eadc8313");
  script_set_attribute(attribute:"solution", value:"Upgrade to ManageEngine ServiceDesk Plus version 8.0.0 build 8015 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:servicedesk_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("manageengine_servicedesk_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/manageengine_servicedesk");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:8080);

install = get_install_from_kb(
  appname :"manageengine_servicedesk",
  port    :port,
  exit_on_fail:TRUE
);
dir         = install['dir'];
install_url = build_url(port:port,qs:dir);
raw_version = install['ver'];
if (raw_version == UNKNOWN_VER) exit(1, "The version of ManageEngine ServiceDesk at "+install_url+" could not be determined.");

pieces = split(raw_version, sep:" Build ", keep:FALSE);
if (isnull(pieces)) exit(1, "Failed to parse the version from the ManageEngine ServiceDesk Plus install at "+install_url+".");
version = pieces[0] + '.' + pieces[1];

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 8 && ver[1] == 0 && ver[2] == 0 && ver[3] < 8015)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + raw_version +
      '\n  Fixed version     : 8.0.0 Build 8015' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The ManageEngine ServiceDesk Plus "+raw_version+" install at "+install_url+" is not affected.");
