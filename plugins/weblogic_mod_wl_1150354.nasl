#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34781);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2008-4008");
  script_bugtraq_id(31683, 31761);
  script_osvdb_id(49283);

  script_name(english:"Oracle WebLogic Server mod_wl Invalid Parameter Remote Overflow (1150354)");
  script_summary(english:"Sends a POST request to get the plug-in's build timestamp");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a module that is affected by a buffer
overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server is using the WebLogic plug-in for Apache
(mod_wl), an Apache module included with Oracle (formerly BEA)
WebLogic Server and used to proxy requests from an Apache HTTP server
to WebLogic. 

The version of this plug-in on the remote host is affected by a stack
buffer overflow that is triggered when processing a request with an
invalid parameter.  An unauthenticated, remote attacker can leverage
this issue to execute arbitrary code on the remote host. 

Note that Nessus has not tried to exploit this issue but rather has
only checked the affected module's build timestamp." );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=751
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e539ff75" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/497969/30/0/threaded" );
  # http://www.oracle.com/technetwork/topics/security/whatsnew/index.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1bbe3e7" );
 script_set_attribute(attribute:"solution", value:
"Install the latest web server plug-in as described in the vendor
advisory above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'BEA Weblogic Transfer-Encoding Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/11/16");
 script_cvs_date("$Date: 2015/09/24 23:21:22 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:weblogic_server");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Make sure the banner looks like Apache.
banner = get_http_banner(port:port);
if (
  !banner || 
  !egrep(pattern:"^Server:.*(Apache|Oracle HTTP Server|IBM_HTTP_SERVER|IBM_HTTP_Server)", string:banner)
) exit(0);


# Iterate over known directories.
dirs = get_kb_list(string("www/", port, "/content/directories"));
if (isnull(dirs)) dirs = make_list("", "/weblogic");

foreach dir (dirs)
{
  # Look for the plug-in and a bridge message.
  url = string(dir, "/index.jsp");

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (res == NULL) exit(0);

  # nb: if there's a problem with configured WebLogic server, the initial
  #     request results in a bridge message we can use to fingerprint the
  #     plug-in. Otherwise, we pass in a special request to "tickle" one.
  if ("X-Powered-By: Servlet" >< res[1])
  {
    res = http_send_recv3(
      method:"POST", 
      item:url, 
      port:port,
      add_headers:make_array("Content-Length", "-1")
    );
    if (res == NULL) exit(0);
  }

  # If it's a bridge message from Apache...
  if (
    "TITLE>Weblogic Bridge Message" >< res[2] ||
    "Failure of server APACHE bridge:</H2>" >< res[2]
  )
  {
    build = "";
    change = "";

    foreach line (split(res[2], keep:FALSE))
    {
      if ("Build date/time:" >< line)
      {
        build = strstr(line, "Build date/time:") - "Build date/time:";
        build = ereg_replace(pattern:"<[^>]+>", replace:"", string:build);
        build = ereg_replace(pattern:"^ +", replace:"", string:build);
      }
      if ("Change Number:" >< line)
      {
        change = strstr(line, "Change Number:") - "Change Number:";
        change = ereg_replace(pattern:"<[^>]+>", replace:"", string:change);
        change = ereg_replace(pattern:"^ +", replace:"", string:change);
      }
      if (build && change) break;
    }

    if (
      (change && int(change) < 1150354) ||
      (
        build && 
        (
          build =~ "^[A-Za-z]{3} ( |[0-3])[0-9] (1[0-9]{3}|200[0-7]) " ||
          build =~ "^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug) ( |[0-3])[0-9] 2008 "
        )
      )
    )
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Nessus was able to retrieve the following information about the remote\n",
          "WebLogic plug-in :\n",
          "\n",
          "  Plug-in type    : Apache\n"
        );
        if (build)
        {
          report = string(
            report,
            "  Build date/time : ", build, "\n"
          );
        }
        if (change)
        {
          report = string(
            report,
            "  Change number   : ", change, "\n"
          );
        }
        if (report_verbosity > 1)
        {
          report = string(
            report,
            "\n",
            "It is configured to proxy requests such as :\n",
            "\n",
            "  ", build_url(port:port, qs:url), "\n"
          );
        }
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
    }

    # We've found the plug-in so we're done.
    exit(0);
  }
}
