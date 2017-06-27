#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61648);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/13 21:07:13 $");

  script_cve_id("CVE-2012-2626", "CVE-2012-2627", "CVE-2012-3848");
  script_bugtraq_id(54725, 54726, 54727);
  script_osvdb_id(84318, 84319, 84320, 84321);

  script_name(english:"Scrutinizer < 9.5.2 Multiple Vulnerabilities");
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
"The version of Scrutinizer running on the remote host is a version
prior to 9.5.2, and is, therefore, potentially affected by the following
vulnerabilities :

  - The 'd4d/exporters.php' and 'd4d/contextMenu.php' web 
    console scripts are affected by multiple cross-site 
    scripting vulnerabilities. (CVE-2012-3848)

  - An arbitrary file creation and file overwrite 
    vulnerability exists in the 'd4d/uploader.php' web 
    console script.  This allows attackers to create or 
    overwrite arbitrary files in
    '%PROGRAMFILES%\Scrutinizer\snmp\mibs\' via an HTTP POST 
    request. (CVE-2012-2627) 

  - The 'cgi-bin/admin.cgi' web console script allows remote,
    unauthenticated attackers to add administrative 
    accounts. (CVE-2012-2626)

Note that Tenable has confirmed the cross-site scripting vulnerabilities
in 9.5.0 even though that version was originally reported to have
addressed those."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.trustwave.com/spiderlabs/advisories/TWSL2012-014.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Scrutinizer 9.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:sonicwall_scrutinizer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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

appname = 'Scrutinizer Netflow & sFlow Analyzer';
install = get_install_from_kb(appname:'scrutinizer_netflow_sflow_analyzer', port:port, exit_on_fail:TRUE);
dir = install['dir'];
app_url = build_url(qs:dir, port:port);

version = install['ver'];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, app_url);

fix = '9.5.2';
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
    '\n  URL               : ' + app_url + 
    '\n  Installed Version : ' + version +
    '\n  Fixed Version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, app_url, version);
