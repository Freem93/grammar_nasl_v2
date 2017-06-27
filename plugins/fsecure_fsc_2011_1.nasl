#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52026);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_cve_id("CVE-2011-0453");
  script_bugtraq_id(46381);
  script_osvdb_id(70898);
  script_xref(name:"Secunia", value:"43326");

  script_name(english:"F-Secure Internet Gatekeeper for Linux Log Disclosure (FSC-2011-1)");
  script_summary(english:"Tries to read fssp.log");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of F-Secure Internet Gatekeeper for Linux installed on the
remote host allows unauthenticated access to log files, which could
allow disclosure of sensitive information.");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN71542734/index.html");
  # http://www.f-secure.com/en_EMEA/support/security-advisory/fsc-2011-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?781eb686");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to F-Secure Internet Gateway for Linux 4.x or apply
Hotfix 1 for version 3.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f-secure:internet_gatekeeper");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("fsecure_igk_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/fsecure_igk");
  script_require_ports("Services/www", 9012);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:9012);

install = get_install_from_kb(appname:"fsecure_igk", port:port, exit_on_fail:TRUE);
dir = install['dir'];


# Try to exploit the issue.
file = 'fssp.log';
file_pat = "[0-9][0-9]: (F-Secure Security Platform|Database version|Starting ArchiveScanner)";

# nb: the Tomcat conf/server.xml file defines two contexts that
#     both point to the log directory.
foreach dir2 (make_list("", "/fsecure"))
{
  url = dir2 + '/log/' + file;
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (egrep(pattern:file_pat, string:res[2]))
  {
    if (report_verbosity > 0)
    {
     header =
        'Nessus was able to exploit the issue to retrieve the contents of\n' +
        "'" + file + "' on the remote host using the following URL";

      line_limit = 10;
      trailer = '';

      if (report_verbosity > 1)
      {
        trailer =
          'Here are its contents (up to ' + line_limit + ' lines) :\n' +
          '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
          beginning_of_response(resp:res[2], max_lines:line_limit) +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);
      }
      report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
exit(0, "The F-Secure Internet Gatekeeper for Linux install at "+build_url(port:port, qs:dir+'/login.jsf')+" is not affected.");
