#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(73275);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id("CVE-2014-1644", "CVE-2014-1645");
  script_bugtraq_id(66399, 66400);
  script_osvdb_id(105090, 105091, 105092);
  script_xref(name:"IAVB", value:"2014-B-0034");

  script_name(english:"Symantec LiveUpdate Administrator < 2.3.2.110 Multiple Vulnerabilities (SYM14-005)");
  script_summary(english:"Checks LUA version");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec LiveUpdate Administrator 2.x hosted on the
remote web server is prior to 2.3.2.110 (2.3.2.1). It is, therefore,
affected by the following vulnerabilities :

  - A flaw exists with the forgotten password functionality
    where the password for an authorized user account can be
    forcefully reset. This could allow a remote attacker
    with knowledge of the account's email address to reset
    the password and potentially gain full access to the
    administrator web interface. (CVE-2014-1644)

  - Multiple SQL injection flaws exist within the
    application, including the password recovery
    functionality. This could allow a remote attacker to
    inject or manipulate SQL queries, allowing the
    manipulation or disclosure of arbitrary data.
    (CVE-2014-1645)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20140328-0_Symantec_LiveUpdate_Administrator_Multiple_vulnerabilities_wo_poc_v10.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd44e0ba");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Mar/171");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2014&suid=20140327_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f25e872c");
  script_set_attribute(attribute:"solution", value:"Upgrade to LiveUpdate Administrator 2.3.2.110 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/31");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:liveupdate_administrator");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_lua_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/symantec_lua");
  script_require_ports("Services/www", 7070, 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:7070);
install = get_install_from_kb(appname:'symantec_lua', port:port, exit_on_fail:TRUE);

dir = install['dir'];
ver = install['ver'];
url = build_url(port:port, qs:dir);

if (ver == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Symantec LiveUpdate Administrator", url);

# Branch Check
if (ver !~ "^2\.") audit(AUDIT_WEB_APP_NOT_AFFECTED,"Symantec LiveUpdate Administrator",url,ver);

fix = '2.3.2.110';
if (ver_compare(ver:ver, fix:fix, strict:FALSE) != -1)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Symantec LiveUpdate Administrator", url, ver);

set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
