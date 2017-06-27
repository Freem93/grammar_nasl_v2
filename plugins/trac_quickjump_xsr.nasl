#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33271);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2008-2951");
  script_bugtraq_id(30402);
  script_osvdb_id(46513);

  script_name(english:"Trac quickjump Search Script q Parameter Arbitrary Site Redirect");
  script_summary(english:"Tries to redirect to a third-party site");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Python script that is affected by a
cross-site redirection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Trac, an enhanced wiki and issue tracking
system for software development projects. 

The version of Trac installed on the remote host fails to sanitize
user input to the 'q' parameter of the 'search' script before using it
in an unfiltered and unmanaged fashion in a redirect.  An attacker may
be able to use an open redirect such as this to trick people into
visiting malicious sites, which could lead to phising attacks, browser
exploits, or drive-by malware downloads." );
 script_set_attribute(attribute:"see_also", value:"http://holisticinfosec.org/content/view/72/45/" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3015c55e" );
 script_set_attribute(attribute:"see_also", value:"http://trac.edgewall.org/wiki/ChangeLog#a0.10.5" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8123ada2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Trac version 0.11.0 / 0.10.5 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/30");
 script_cvs_date("$Date: 2016/05/06 17:22:02 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Loop through directories.
if (thorough_tests) dirs = list_uniq("/trac", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # NB: redirect_url only gets echoed back in the response.
  redirect_url = "http://www.nessus.org/";
  url = string(dir, "/search?q=", redirect_url);

  r = http_send_recv3(method: "GET", item:url, port:port);
  if (isnull(r)) exit(0);

  # Make sure the output looks like it's from Trac.
  if (egrep(pattern:"^Set-Cookie: +trac_", string: r[1]))
  {
    # There's a problem if we're redirected to our URL.
    location = egrep(pattern:"^Location:", string:r[1], icase:TRUE);
    if (location && redirect_url >< location)
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to exploit the issue using the following URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
