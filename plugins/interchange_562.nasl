#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41056);
  script_version("$Revision: 1.7 $");

  script_bugtraq_id(36452);
  script_osvdb_id(58206);
  script_xref(name:"Secunia", value:"36716");

  script_name(english:"Interchange < 5.4.4 / 5.6.2 / 5.7.2 Search Request Information Disclosure");
  script_summary(english:"Checks the version of Interchange");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server uses an application server that may be prone to
an information disclosure vulnerability."  );
  
  script_set_attribute( attribute:"description", value:
"The remote host appears to be running Interchange, an open source
application server that handles state management, authentication,
session maintenance, click trails, filtering, URL encodings, and
security policy. 

According to the banner in its administrative login page, the
installed version of Interchange is earlier than 5.4.4 / 5.6.2 /
5.7.2.  Such versions are potentially affected by an information
disclosure vulnerability.  Any database table configured within
Interchange can be queried remotely by an unauthenticated user because
the application fails to limit access from its search functions."  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://ftp.icdevgroup.org/interchange/5.6/ANNOUNCEMENT-5.6.2.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.icdevgroup.org/i/dev/news?mv_arg=00038"
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Interchange 5.4.4 / 5.6.2 / 5.7.2 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/17"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/23"
  );
 script_cvs_date("$Date: 2011/03/14 21:48:06 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

#Search for interchange
if (thorough_tests) dirs = list_uniq(make_list("/interchange", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  #Request admin homepage
  url = string(dir, "/admin/login.html");
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

  #If it looks like Interchange
  if (
    '<INPUT TYPE=hidden NAME=mv_nextpage VALUE="admin/index">' >< res[2] &&
    egrep(pattern:'^<FORM ACTION=".*/process.*" METHOD=POST name=login>', string:res[2])
  )
  {
    version = egrep(pattern:".*([0-9\.]+) &copy;.*Interchange Development Group&nbsp;", string:res[2]);
    version = version - strstr(version, ' &copy;');
    version = ereg_replace(string:version, pattern:".*([0-9]+\.[0-9]+\.[0-9]+)", replace:"\1");
    if (
      version =~ "^([0-4]\.[0-9\.]+|5\.([0-3]\.[0-9]+|5\.[0-9]+))$" ||
      version =~ "^5\.(4\.[0-3]|6\.[01]|7\.[01])$"
    )
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          " URL     : ", build_url(port:port, qs:url), "\n",
          " Version : ", version, "\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
  }
}
