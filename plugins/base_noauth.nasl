#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39535);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_name(english:"Basic Analysis and Security Engine Authentication Check");
  script_summary(english:"Verifies if authentication is required");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application can be accessed without authentication.");
  script_set_attribute(attribute:"description", value:
"Basic Analysis and Security Engine (BASE) is installed on the remote
system.  It is possible to access the remote web application without
any authentication.  This allows anyone to not only browse anomalous
network traffic but also obtain detailed information about the
underlying OS, installed version of PHP and the database being used. 
A malicious attacker could leverage this information to launch other
attacks against the system.");

  script_set_attribute(attribute:"solution", value:
"Configure the application to require authentication." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");


 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/26");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:secureideas:basic_analysis_and_security_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/base", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/base_main.php");

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);
 
  if(
    "Basic Analysis and Security Engine" >< res[2] &&
     ">Alert Group Maintenance<" >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "BASE is accessible at the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
