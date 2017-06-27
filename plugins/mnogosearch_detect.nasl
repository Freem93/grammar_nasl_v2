#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65901);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/10 19:51:13 $");

  script_name(english:"mnoGoSearch Detection");
  script_summary(english:"Looks for mnoGoSearch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server hosts a web search engine application."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts mnoGoSearch, a CGI-based web search engine
application formerly known as UdmSearch."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mnogosearch.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mnogosearch:mnogosearch");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

if (thorough_tests) dirs = list_uniq(make_list("/search", cgi_dirs()));
else dirs = make_list(cgi_dirs());

files = make_list("/search.cgi", "/search.pl", "/search.exe");

installs = make_array();
pat =  'Powered by (mnoGoSearch|' +
  '\\<A HREF="http://search.mnogo.ru/"\\>(UdmSearch|mnoGoSearch)|' +
  '\\<a href="http://mysearch.udm.net/"\\>UdmSearch)|' +
  '\\<a href="http://(my)?search.(udm.net|mnogo.ru)';

pat2 = '(VALUE|value)="Search!"';

# Version information was not available until versions 3.3.x and up
ver_pat = "Powered by mnoGoSearch ([0-9\.]+) -";
version = UNKNOWN_VER;

foreach dir (dirs)
{
  foreach file (files)
  {
    res = http_send_recv3(
      method       : "GET",
      port         : port,
      item         : dir + file,
      exit_on_fail : TRUE
    );

    if (res[2] =~ pat && res[2] =~ pat2)
    {
      ver_match = eregmatch(string:res[2], pattern: ver_pat);
      if (!isnull(ver_match)) version = ver_match[1];

      installs = add_install(
        installs : installs,
        port     : port,
        dir      : dir + file,
        appname  : 'mnogosearch',
        ver      : version
      );
      if (!thorough_tests)
        break;
    }
  }
}

if (max_index(keys(installs)) == 0) audit(AUDIT_WEB_APP_NOT_INST, "mnoGoSearch", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : "mnoGoSearch",
    installs     : installs,
    port         : port,
    item         : ""
  );
  security_note(port:port, extra:report);
}
else security_note(port);
