
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36100);
  script_version("$Revision: 1.8 $");

  script_name(english:"mod_perl Apache::Status Info Disclosure");
  script_summary(english:"Tries to access mod_perl status page");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server discloses information about its status."
  );
  script_set_attribute( attribute:"description",  value:
"It is possible to obtain an overview of the Perl interpreter embedded
in the remote Apache server.  This overview includes information such
as loaded modules, Perl configuration, and settings of environment
variables."  );
  script_set_attribute( attribute:"solution",  value:
"Ensure that access to Apache::Status / Apache2::Status is limited to
valid users / hosts or, if it's not needed, update Apache's
configuration file to disable use of this handler."  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/07");
 script_cvs_date("$Date: 2015/09/24 21:17:12 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);


# Unless we're being paranoid, make sure the banner looks like Apache.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) exit(0);
  if (!egrep(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/", string:banner)) exit(0);
}


# Loop through directories.
dirs = list_uniq(make_list("/perl-status", cgi_dirs()));
if (thorough_tests) dirs = list_uniq(dirs, "/status");

foreach dir (dirs)
{
  if (strlen(dir) == 0) dir = "/";
  res = http_send_recv3(method:"GET", item:dir, port:port, exit_on_fail: 1);

  if (
    (
      "title>Apache::Status " >< res[2] ||
      "title>Apache2::Status " >< res[2] ||
      '?env">Environment' >< res[2]
    ) &&
    "Embedded Perl version <b>" >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to access the status page using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:dir), "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
