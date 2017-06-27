#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35618);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2009-0348");
  script_bugtraq_id(33489);
  script_osvdb_id(51666);
  script_xref(name:"Secunia", value:"33688");

  script_name(english:"Sun OpenSSO / Java System Access Manager Login Module User Account Enumeration Weakness");
  script_summary(english:"Queries several user accounts");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a module that leaks information." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sun OpenSSO, or Sun Java System Access
Manager as it was previously known, an enterprise-class product that
provides web access management, federation, and web services security. 

The version of the Login module included with Sun OpenSSO / Sun Java
System Access Manager on the remote host allows an unauthenticated,
remote attacker to enumerate users during the login phase using
specially crafted requests." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01ee02e7" );
 script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1019602.1.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor advisory above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/09");
 script_cvs_date("$Date: 2016/05/04 14:21:28 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
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

users = make_list(
  string("nessus-", unixtime()),        # hopefully bogus
  "amAdmin",                            # hopefully good
  "admin",                              # ??
  "guest"                               # ??
);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/amserver", "/opensso", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Iterate over users looking for different responses.
  titles = make_array();
  user_existent = NULL;
  user_nonexistent = NULL;

  foreach user (users)
  {
    url = string(dir, "/UI/Login?user=");
    res = http_send_recv3(method:"GET", item:url+user, port:port);
    if (isnull(res)) exit(0);

    if ("<title>Sun " >!< res[2]) break;

    # Isolate the title.
    title = strstr(res[2], "<title>") - "<title>";
    title = title - strstr(title, "</title>");

    if (isnull(user_nonexistent) && "(User Inactive)" >< title)
    {
      user_nonexistent = user;
      titles[user] = title;
    }
    else if (
      isnull(user_existent) && 
      (
        "(No Configuration Error)" >< title ||
        "(Your account has been locked)" >< title
      )
    )
    {
      user_existent = user;
      titles[user] = title;
    }

    if (user_existent && user_nonexistent)
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to verify the issue with the following queries and\n",
          "responses :\n",
          "\n",
          "  Existing User  : ", user_existent, "\n",
          "  URL            : ", build_url(port:port, qs:url), user_existent, "\n",
          "  Response Title : ", titles[user_existent], "\n",
          "\n",
          "  Invalid User   : ", user_nonexistent, "\n",
          "  URL            : ", build_url(port:port, qs:url), user_nonexistent, "\n",
          "  Response Title : ", titles[user_nonexistent], "\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
