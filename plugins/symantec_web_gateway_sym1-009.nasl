#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86150);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/18 14:03:59 $");

  script_cve_id(
    "CVE-2015-5690",
    "CVE-2015-5691",
    "CVE-2015-5692",
    "CVE-2015-5693",
    "CVE-2015-6547",
    "CVE-2015-6548");
  script_bugtraq_id(
    76725,
    76726,
    76728,
    76729,
    76730,
    76731
  );
  script_osvdb_id(
    127689,
    127690,
    127691,
    127692,
    127693,
    127694
  );

  script_name(english:"Symantec Web Gateway Database < 5.0.0.1277 Multiple Vulnerabilities (SYM15-009) (credentialed check)");
  script_summary(english:"Checks the SWG version.");

  script_set_attribute(attribute:"synopsis", value:
"A web security application hosted on the remote web server is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote web server
is hosting a version of Symantec Web Gateway with a database component
prior to version 5.0.0.1277. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists that allows the bypassing of access
    redirect restrictions. An authenticated, remote attacker
    can exploit this to inject commands with elevated
    privileges. (CVE-2015-5690)

  - A reflected cross-site scripting vulnerability exists
    in the management console due to improper validation of
    user-supplied input. An attacker can exploit this to
    execute arbitrary script in the user's browser session.
    (CVE-2015-5691)

  - A flaw exists in the admin_messages.php script due to
    improperly sanitizing user-uploaded files. An attacker
    can exploit this to execute arbitrary PHP code via a
    crafted file. (CVE-2015-5692)

  - A flaw exists related to Traffic Capture EoP due to the
    Hostname field in the administrator configuration
    facility not properly sanitizing user-supplied input
    before writing it to the '/etc/sysconfig/network' file,
    which is processed during startup and shutdown. An
    authenticated, remote attacker can exploit this, via a
    crafted hostname, to inject commands which are executed
    with root privileges. (CVE-2015-5693)

  - An unspecified flaw exists exists related to the Boot
    Time EoP. An authenticated, remote attacker can exploit
    this to inject arbitrary commands. (CVE-2015-5647)

  - A flaw exists in the edit_alert.php script due to not
    properly sanitizing user-supplied input to the 'alertid'
    and 'applianceid' GET parameters. An authenticated,
    remote attacker can exploit this to inject or manipulate
    SQL queries, resulting in the disclosure of arbitrary
    data. (CVE-2015-6548)");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20150916_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b4ff35b");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-443/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-444/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Web Gateway Database to 5.0.0.1277 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:web_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_web_gateway_detect.nasl");
  script_require_keys("installed_sw/symantec_web_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

port = get_http_port(default:443, php:TRUE);
app = 'Symantec Web Gateway';

install = get_single_install(
  app_name : 'symantec_web_gateway',
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];
url = build_url(port:port, qs:dir);

# 5.2.3 is not released, but this is for future-proofing.
fix = '5.2.3';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);
}


# We don't want to require these keys in the case of versions > 5.2.2
user = get_kb_item_or_exit("http/login");
pass = get_kb_item_or_exit("http/password");

post_data =
"USERNAME="+user+"&PASSWORD="+pass+"&loginBtn=Login";

# Logging in to get the DB version
res = http_send_recv3(
    method      : "POST",
    item        : "/spywall/login.php",
    data        : post_data,
    port        : port,
    follow_redirect: 1,
    content_type: 'application/x-www-form-urlencoded',
    exit_on_fail: TRUE
);

# If the login fails, the server returns a 200, which isn't helpful. We
# need to match content.
if(res[2] !~ "<title>Symantec Web Gateway.*Executive Summary</title>")
  exit(0, "Login for " + app + " failed.");

res2 = http_send_recv3(
    method      : "GET",
    item        : "/spywall/executive_summary.php",
    port        : port,
    exit_on_fail: TRUE
);

db_fix = '5.0.0.1277';
db_ver = NULL;

# This string floats in a large blob of text, anchoring is not going
# to provide any great utility
if("Current Database Version" >< res2[2])
{
  matches = eregmatch(pattern:"Current Database Version: ([0-9.]+);",
                      string: res2[2]);
  db_ver = matches[1];
  if (empty_or_null(db_ver))
    audit(AUDIT_UNKNOWN_WEB_APP_VER, app + " Database", url);
}
else
  audit(AUDIT_UNKNOWN_WEB_APP_VER, app + " Database", url);

report = NULL;

if (ver_compare(ver:db_ver, fix:db_fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
     report =
       '\n  URL                           : ' + url +
       '\n  Installed application version : ' + ver +
       '\n  Installed database version    : ' + db_ver +
       '\n  Fixed database version        : ' + db_fix + '\n';
  }

  security_hole(port:port, extra:report);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app + " Database", url, db_ver);
