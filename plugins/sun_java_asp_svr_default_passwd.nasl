#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33437);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/12/14 20:33:27 $");

 script_name(english:"Sun Java ASP Server Default Admin Password");
 script_summary(english:"Attempts to access remote ASP server with default admin credentials");

 script_set_attribute(attribute:"synopsis", value:"The remote web server can be accessed with default admin credentials.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Sun Java ASP server.

It is possible to access the remote server with default admin
credentials.");
 script_set_attribute(attribute:"see_also", value:"http://docs.sun.com/source/817-2514-10/index.html");
 script_set_attribute(attribute:"solution", value:
"Follow the steps outlined in the vendor advisory referenced above to
change the admin password immediately.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/08");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("http_version.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/www", 5100);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

#
# The script code starts here
#

port = get_http_port(default:5100);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Request for admin page
r = http_send_recv3(method: "GET", item:"/caspadmin/index.asp", port:port, username: "", password: "", exit_on_fail:TRUE);


if ("401 Authorization Required" ><  r[0] &&
    "ASP Management Server"	>< r[1]+r[2]
   )
{
  # Try default combinations.
  combinations = make_list("admin:root","admin:admin","admin:password");

  foreach combination (combinations)
  {
   v = split(combination, sep: ':', keep: 0);
   r = http_send_recv3(method: "GET", item:"/caspadmin/index.asp", port:port,
     username: v[0], password: v[1], exit_on_fail:TRUE);
    if("Location: /caspadmin/server.props.asp" >< r[1] &&
       "Set-Cookie:" >< r[1]
    )
    {
      if (report_verbosity)
      {
       report = string ("\n",
	"Nessus was able to login into the remote ASP server with\n",
        "default admin credentials : ",combination,"\n\n",
        "Please change the password immediately\n\n"
	);
      security_hole(port:port,extra:report);
     }
     else
      security_hole(port);
    exit(0);
   }
  }
}

