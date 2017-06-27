#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65046);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/13 21:07:13 $");

  script_bugtraq_id(57914, 57949);
  script_osvdb_id(
    90188,
    90213,
    90214,
    90215,
    90216,
    90217,
    90218
  );
  script_xref(name:"EDB-ID", value:"24496");
  script_xref(name:"EDB-ID", value:"24500");

  script_name(english:"Scrutinizer < 10.1.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Scrutinizer");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Scrutinizer NetFlow and sFlow Analyzer running on the
remote host is a version prior to 10.1.2, and is, therefore, potentially
affected by the following vulnerabilities :

  - A blind SQL injection vulnerability exists because the
    'orderby' and 'gadget' parameters of 'fa_web.cgi'
    fail to properly sanitize user-supplied input.  This
    may allow an attacker to inject or manipulate SQL
    queries in the back-end database.

  - The application is affected by multiple persistent
    cross-site scripting vulnerabilities in the following
    parameters / modules :

     - 'BBSearchText' - New Board & Policy Manager
     - 'Mytab' - Flow Expert
     - 'newName'  - MyView (CGI)
     - 'groupName' - New Users & New Group
     - 'username' - New Users & New Group
     - 'groupMembers' - Mapping /Maps (CGI)
     - 'Type' - Mapping /Maps (CGI)
     - 'Checkbox Linklike' - Mapping /Maps (CGI)
     - 'indexColumn' - Mapping /Maps (CGI)
     - 'name' - Mapping /Maps (CGI)
     - 'Object Name' - Mapping /Maps (CGI)
     - 'settings groups(checkbox)' - Mapping /Maps (CGI)
     - 'Policy Name' - Advanced Filters
     - 'Board Name' - Advanced Filters
     - 'Violators' - Advanced Filters

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Feb/57");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Feb/58");
  # http://www.sonicwall.com/us/shared/download/Support_Bulletin_-_Scrutinizer_Vulnerabilities_130222.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92c27f55");
  script_set_attribute(attribute:"solution", value:"Upgrade to Scrutinizer 10.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:sonicwall_scrutinizer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("scrutinizer_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/scrutinizer_netflow_sflow_analyzer");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

appname = 'Scrutinizer NetFlow and sFlow Analyzer';

install = get_install_from_kb(appname:'scrutinizer_netflow_sflow_analyzer', port:port, exit_on_fail:TRUE);
dir = install['dir'];
app_url = build_url(qs:dir, port:port);

version = install['ver'];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, app_url);

fix = '10.1.2';
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
    '\n  URL               : ' + app_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, app_url, version);
