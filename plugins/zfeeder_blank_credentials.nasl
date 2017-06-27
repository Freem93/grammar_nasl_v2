#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35803);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_cve_id("CVE-2009-0807");
  script_osvdb_id(52358);
  script_xref(name:"EDB-ID", value:"8092");

  script_name(english:"zFeeder admin.php Direct Request Admin Authentication Bypass");
  script_summary(english:"Tries to access configruation settings");

  script_set_attribute(  attribute:"synopsis",  value:
"The remote web server allows unauthenticated access to its admin
panel."  );
  script_set_attribute( attribute:"description",   value:
"The remote host is running zFeeder, an open source PHP application
used to aggregate RSS content.

The remote installation of zFeeder is configured by default using
empty values for the admin's username and password.  A remote attacker
can leverage this issue to gain administrative control of the affected
application."  );
  script_set_attribute( attribute:"solution",  value:
"Access the application's admin panel and change the admin username and
password."  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/newsfeeds", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # See if admin.php exists and allows uncredentialed configuration access.
  url = string(dir, "/admin.php?zfaction=config");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res))exit(0);

  if ("username :</font>" >< res[2])
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to access the admin panel with empty credentials\n",
        "using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
