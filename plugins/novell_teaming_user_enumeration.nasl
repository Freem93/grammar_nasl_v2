#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(36205);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2009-1293");
  script_bugtraq_id(34531);
  script_osvdb_id(53936);
  script_xref(name:"Secunia", value:"34714");

  script_name(english:"Novell Teaming Login User Account Enumeration Weakness");
  script_summary(english:"Queries several user accounts");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a module that leaks information." );
  script_set_attribute(attribute:"description", value:
"The remote host is running Novell Teaming, a collaboration and
conferencing application.  The version of Novell Teaming installed on
the remote host allows an unauthenticated remote attacker to enumerate
users during the login phase because the web application responds with
different messages when an invalid username or invalid password is
used. 

In addition, it is likely to be affected by multiple cross-site
scripting vulnerabilities due to its failure to sanitize input to the
'p_p_state' and 'p_p_mode' parameters of the web application, although
Nessus has not checked for these.");

  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/502704/30/0/threaded" );
  # http://www.novell.com/support/kb/doc.php?id=7002997
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05eaae82" );
  # http://www.novell.com/support/kb/doc.php?id=7002999
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9e444a0" );
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor advisory above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/21");
 script_set_attribute(attribute:"patch_publication_date", value: "2009/04/14");
 script_cvs_date("$Date: 2015/09/24 21:17:13 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

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
  string("nessus-", unixtime()),     # hopefully bogus
  "admin",                           # hopefully good
  "guest"                            # ??
);

password = string("nessus-", unixtime());


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/teaming", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  errors = make_array();
  user_existent = NULL;
  user_nonexistent = NULL;
  password_var = NULL;
  url = string(dir, "/c/portal/login");

  # We have to determine the value of the password variable from the initial connection
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);
  if ("<title>Novell Teaming" >!< res[2]) break;

  if ("_password" >< res[2]){
    matches = eregmatch(pattern:'<input name="([A-Za-z]+_password)"', string:res[2]);
    password_var = matches[1];
  }

  foreach user (users)
  {
    postdata = string(
      "cmd=already-registered", "&",
      "tabs1=already-registered", "&",
      "rememberMe=false","&",
      "login=", user, "&",
      password_var, "=", password
    );
    res = http_send_recv3(method:"POST", data:postdata, add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"), item:url, port:port);
    if (isnull(res)) exit(0);

    if (isnull(user_nonexistent) && "Please enter a valid login." >< res[2])
    {
      user_nonexistent = user;
      error = strstr(res[2], "Please enter a valid login.");
      errors[user] = error - strstr(error, "</span>");
    }
    else if (
      isnull(user_existent) && "Authentication failed. Please try again." >< res[2])
    {
      user_existent = user;
      error = strstr(res[2], "Authentication failed. Please try again.");
      errors[user] = error - strstr(error, "</span>");
    }

    if (user_existent && user_nonexistent)
    {
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Nessus was able to verify the issue with the following queries and\n",
          "responses :\n",
          "  Existing User  : ", user_existent, "\n",
          "  URL            : ", build_url(port:port, qs:url), "\n",
          "  Response Error : ", errors[user_existent], "\n",
          "\n",
          "  Invalid User   : ", user_nonexistent, "\n",
          "  URL            : ", build_url(port:port, qs:url), "\n",
          "  Response Error : ", errors[user_nonexistent], "\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
