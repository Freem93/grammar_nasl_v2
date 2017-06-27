#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33822);
  script_version("$Revision: 1.9 $");

  script_name(english:"XAMPP Example Pages Detection");
  script_summary(english:"Tries to access XAMPP's examples");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server allows access to its example pages." );
 script_set_attribute(attribute:"description", value:
"The remote web server makes available example scripts from XAMPP, an
easy-to-install Apache distribution containing MySQL, PHP, and Perl. 
Allowing access to these examples is not recommended since some are
known to disclose sensitive information about the remote host and
others may be affected by vulnerabilities such as cross-site scripting
issues.  Additionally, some pages have known cross-site scripting,
SQL injection, and local file inclusion vulnerabilities." );
 script_set_attribute(attribute:"solution", value:
"Consult XAMPP's documentation for information about securing the
example pages as well as other applications if necessary." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/05");
 script_cvs_date("$Date: 2015/09/24 23:21:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Call up the default URL.
url = "/xampp/index.php";

r = http_send_recv3(method:"GET", port:port, item: url, exit_on_fail: 1);
res = r[2];

# There's a problem if we see XAMPP's frameset.
if (
  ("<title>XAMPP for" >< res || "<title>XAMPP Version") &&
  '<frame name="navi" src="navi.php"' >< res
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Nessus was able to access XAMPP's examples using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'The remote web server on port '+port+' is not affected.');
