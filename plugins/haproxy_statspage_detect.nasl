#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(59797);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/09/10 18:18:30 $");

  script_name(english:"HAProxy Statistics Page Detection");
  script_summary(english:"Detects HAProxy Statistics Page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a load balancer with a web-based statistics
page."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running HAProxy web-based statistics page. This
page may contain sensitive information about internal network
infrastructure and version information for HAProxy."
  );
  script_set_attribute(attribute:"see_also",value:"http://haproxy.1wt.eu/");
  script_set_attribute(
    attribute:"solution",
    value:
"Password protect page or restrict access to trusted networks / hosts."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"plugin_publication_date",value:"2012/06/29");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:haproxy:haproxy");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl", "webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");
include("webapp_func.inc");

appname = "HAProxy Statistics Page";

# request limit if thorough_tests is enabled
max_url_list_len = 10;

port = get_http_port(default:8080);

url_list = make_list("/");

files = get_kb_list("www/"+port+"/content/extensions/*");

if (!isnull(files))
{
  foreach file (make_list(files))
  {
    if (
      "haproxy" >< tolower(file)  
    ) url_list = make_list(url_list, file);
    if(max_index(url_list) >= max_url_list_len && !thorough_tests)
      break;    
  }
}

installs = NULL;

foreach url (url_list)
{
  res = http_send_recv3(item:url, port:port, method:"GET", exit_on_fail:TRUE);
  if (
    "<title>Statistics Report for HAProxy</title>" >< res[2] &&
    "General process information" >< res[2]
  )
  {
    version = "unknown";
    item = eregmatch(pattern: ">HAProxy version ([^,<]+)(<|[^<]+)<", string:res[2]);
    if(!isnull(item[1]))
      version = item[1];

    installs = add_install(
      appname  : "haproxy_stats_page",
      installs : installs,
      port     : port,
      dir      : url,
      ver      : version
    );
    
    if (!thorough_tests)
      break;
  }
}

if (isnull(installs)) audit(AUDIT_NOT_DETECT, appname, port);

if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    item         : "",
    display_name : appname
  );
  security_warning(port:port, extra:report);
}
else security_warning(port);

exit(0);
