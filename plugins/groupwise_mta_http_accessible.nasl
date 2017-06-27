#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35725);
  script_version("$Revision: 1.10 $");

  script_name(english:"Novell GroupWise MTA Web Console Accessible");
  script_summary(english:"Tries to access the MTA Web Console");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server allows unauthenticated access to administrative
tools."  );
  script_set_attribute( attribute:"description",  value:
"The remote web server is a Novell GroupWise MTA Web Console, used to
monitor and potentially control a GroupWise MTA via a web browser.

By allowing unauthenticated access, anyone may be able to do things
such as discover the version of GroupWise installed on the remote host 
and its configuration, track GroupWise message traffic, or change the
MTA's configuration settings."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.novell.com/documentation/gw65/gw65_admin/data/a7xzvr1.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.novell.com/documentation/gw7/gw7_admin/data/a7xzvr1.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.novell.com/documentation/gw8/gw8_admin/data/a7xzvr1.html"
  );
  script_set_attribute( attribute:"solution",  value:
"Consult the GroupWise Administration Guide for information about
restricting access to the MTA Web Console."  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/21");
 script_cvs_date("$Date: 2015/09/24 21:08:39 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 7180);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:7180, embedded: 1);


# Call up the default URL.
url = "/";
res = http_get_cache(item:url, port:port, exit_on_fail: 1);


# There's a problem if we were able to access the console.
if ("<HEAD><TITLE>GroupWise MTA -" >< res)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to access the remote GroupWise install's MTA Web\n",
      "Console using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
