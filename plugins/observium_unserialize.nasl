#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95391);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_osvdb_id(147093);

  script_name(english:"Observium PHP Object Unserialization Remote File Writing Vulnerability");
  script_summary(english:"Attempts to unserialize a PHP object.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Observium server is affected by a remote file writing
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Observium server is affected by a remote file writing
vulnerability in the var_decode() function in common.inc.php due to
improper validation of user-supplied GET, POST and COOKIE values
before use in the PHP unserialize() function. An unauthenticated,
remote attacker can exploit this to write data to arbitrary files,
including a PHP session file that allows the attacker to gain
administrative privileges.

Note that Observium is reportedly affected by additional
vulnerabilities; however, Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"https://computest.nl/advisories/CT-2016-1110_Observium.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to an Observium version released on or after 2016/10/26.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:observium_limited:observium");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("observium_detect.nasl");
  script_require_keys("installed_sw/Observium");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = 'Observium';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80, php:TRUE);
install = get_single_install(app_name:appname, port:port);

# The premise of this script is this:
# 
# Observium would unserialize any variable provided
# by the user. The vuln (osvdb 147093) leverages this to
# write files. We don't want to write files though. However,
# Observium will alter the HTML of index.php if we can get
# specific variables unserialized.
#
# Therefore we will test if this is patched by comparing
# some HTML before and after unserialization. If the HTML
# is different we know that the unserialization worked.

resp = http_send_recv3(
  method:'POST',
  port:port,
  item:'/');

# the html in question is the body tag
pattern = '(<body[^>]*>)';
firstBody = eregmatch(pattern:pattern, string:resp[2]);
if (isnull(firstBody)) audit(AUDIT_RESP_BAD, port, "a POST request", "http");

resp = http_send_recv3(
  method:'POST',
  port:port,
  item:'/',
  content_type:'application/x-www-form-urlencoded',
  data:'bare=czozOiJ5ZXMiOw==');

secondBody = eregmatch(pattern:pattern, string:resp[2]);
if (isnull(secondBody)) audit(AUDIT_RESP_BAD, port, "a POST request", "http");

if (firstBody[1] == secondBody[1])
{
  audit(AUDIT_INST_VER_NOT_VULN, appname, install['version']);
}

report =
  '\nNessus was able to exploit a PHP unserialization vulnerability by' +
  '\nsending a crafted HTTP request.' +
  '\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
