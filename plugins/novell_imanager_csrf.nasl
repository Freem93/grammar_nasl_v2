#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66036);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/04/26 10:54:13 $");

  script_cve_id("CVE-2013-1088", "CVE-2013-3268");
  script_bugtraq_id(59042, 59450);
  script_osvdb_id(92270, 92269);

  script_name(english:"Novell iManager < 2.7.6 Patch 1 Multiple Vulnerabilities");
  script_summary(english:"Checks version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web application is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Novell iManager installed on the remote host is earlier
than 2.7.6 Patch 1 and therefore affected by multiple vulnerabilities :

  - There is an unspecified cross-site request forgery
    vulnerability. (CVE-2013-1088)

  - A flaw exists due to the software not properly
    terminating session tokens after logout may allow an
    attacker with access to a user's network traffic to gain
    access to the account via a session replay attack.
    (CVE-2013-3268)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7010166");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the Novell iManager 2.7.6 Patch 1 or higher."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:imanager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("novell_imanager_detect.nasl");
  script_require_keys("www/novell_imanager");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("datetime.inc");
include("webapp_func.inc");

port = get_http_port(default:8443);

appname = "Novell iManager";

install = get_install_from_kb(appname:'novell_imanager', port:port, exit_on_fail:TRUE);
version = install['ver'];

url = build_url(port:port, qs:install['dir'] + '/');

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, url);

# patch adds version.properties
# we can check the date in this file to verify patch has been applied
version_properties = get_kb_item('www/'+port+'/novell_imanager/version_properties');

vuln = FALSE;

ver = split(version, sep:".", keep:FALSE);

if (ver[0] == 2 && ver[1] == 7 && ver[2] < 6)
  vuln = TRUE;

# if the version.properties file is missing, we are vuln
if (ver[0] == 2 && ver[1] == 7 && ver[2] == 6 && !version_properties)
  vuln = TRUE;

if (ver[0] == 2 && ver[1] == 7 && ver[2] == 6 && !vuln)
{
  ##Tue Apr 09 16:29:27 IST 2013
  #version=2.7.6
  item = eregmatch(pattern:"[A-Za-z]{3} ([A-Za-z]{3}) ([0-9]{2}) [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Za-z]{3} ([0-9]{4})", string:version_properties);
  if (isnull(item)) exit(1, "Version 2.7.6 of NetIQ iManager is installed, however we are unable to determine the service pack level from the version.properties file.");

  month = int(month_num_by_name(base:1, item[1]));
  day = int(item[2]);
  year = int(item[3]);

  if (
    year < 2013 ||
    (year == 2013 && month < 4) ||
    (year == 2013 && month == 4 && day < 9)
  )
    vuln = TRUE;
  else
    version += " Patch 1";
}

if (vuln)
{
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
  if (report_verbosity > 0)
  {
    report = '\n  URL               : ' + url +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 2.7.6 Patch 1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
