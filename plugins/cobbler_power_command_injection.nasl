#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59402);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/24 02:02:50 $");

  script_cve_id("CVE-2012-2395");
  script_bugtraq_id(53666);
  script_osvdb_id(82458);

  script_name(english:"Cobbler xmlrpc API power_system Method Remote Shell Command Execution");
  script_summary(english:"Checks version of Cobbler");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote service is affected by a command injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the Cobbler install on the
remote host is affected by a command injection vulnerability that can
be exploited by sending a specially crafted username or password
argument to the 'power_system' method. 

Successful exploitation requires an authenticated user and xmlrpc API
access."
  );
   # https://github.com/cobbler/cobbler/commit/6d9167e5da44eca56bdf42b5776097a6779aaadf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c3391f4");
  script_set_attribute(attribute:"see_also", value:"https://github.com/cobbler/cobbler/issues/141");
  script_set_attribute(attribute:"see_also", value:"https://bugs.launchpad.net/ubuntu/+source/cobbler/+bug/978999");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to the latest developmental version of Cobbler or apply the
fixes manually."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:michael_dehaan:cobbler");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
 
  script_dependencies("cobbler_admin_detect.nasl", "cobbler_xmlrpc_detect.nasl");
  script_require_keys("www/cobbler/xmlrpc", "Settings/ParanoidReport", "www/cobbler_web_admin");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("datetime.inc");
include("webapp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

install = get_install_from_kb(appname:'cobbler_web_admin', port:port, exit_on_fail:TRUE);

appname = "Cobbler";
kb_base = "www/" + port + "/cobbler/xmlrpc/";
	
version = get_kb_item_or_exit(kb_base + "Version");
url = build_url(port:port, qs:install['dir'] + '/');

if (version == 'unknown') audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, url);

gitdate = get_kb_item_or_exit(kb_base + "GitDate");
gitstamp = get_kb_item_or_exit(kb_base + "GitStamp");

item = eregmatch(pattern:"[A-Z][a-z]{2} ([A-Z][a-z]{2}) ([0-9]{1,2}) [0-9]{2}:[0-9]{2}:[0-9]{2} ([0-9]{4}) ", string:gitdate);
if (isnull(item)) exit(1, "Failed to parse '"+kb_base+"GitDate' KB item.");

month = int(month_num_by_name(base:1, item[1]));
day = int(item[2]);
year = int(item[3]);

if (
  # author says next release (2.2.3) will have fix
  ver_compare(ver:version, fix:'2.2.3',strict:FALSE) == -1 ||
  (version =~ "^2\.3\." && # version of current developmental master branch with fix 
    ( 
     year < 2012 ||
    (year == 2012 && month < 5) ||
    (year == 2012 && month == 5 && day < 6) ||
    (year == 2012 && month == 5 && day == 6 && 
     gitstamp != "1003578" && gitstamp != "6d9167e")
    )
  )
)
{
  if(report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version + ' (Git Date : ' + gitdate + ')' + 
             '\n  Fixed version     : 2.3.1 (Git Date : Sun May 6 21:15:27 2012 -0700)\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, appname, port, version + ' (Git Date : ' + gitdate + ')');  
