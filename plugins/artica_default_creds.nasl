#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50324);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_name(english:"Artica Default Credentials");
  script_summary(english:"Attempts to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application can be accessed with default credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into Artica's web management console using
default credentials.");
  script_set_attribute(attribute:"see_also", value:"http://www.artica.fr/");
  script_set_attribute(attribute:"solution", value:
"Refer to vendor supplied documentation for instructions about changing
the default password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("artica_detect.nasl");
  script_require_ports("Services/www", 9000);
  script_require_keys("www/artica","www/lighttpd");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:9000);

install = get_install_from_kb(appname:'artica', port:port, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
dir = install['dir'];

url = "/logon.php";

logins = make_list("Manager", "admin");
password = "secret";
info     = '';

foreach login (logins)
{
 # Send a login POST request.
  res = http_send_recv3(
          method:"POST", 
          item:url, 
          port:port,
          content_type:"application/x-www-form-urlencoded",
          data:'artica_username='+login+'&artica_password='+password+'&lang=en',
          exit_on_fail:TRUE
  );

  if ('location:admin.index.php' >< res[2] && "bad password" >!< res[2])
  {
    # Double check by sending a request to a page that definitely
    # requires credentials.
    
    res = http_send_recv3(method:"GET", item:"/admin.index.php", port:port,exit_on_fail:TRUE);

    if ("Welcome on Artica-Postfix Administrator" >< res[2])
    {
      info += '\n  User     : ' + login + 
              '\n  Password : ' + password + '\n';
   
      # Be nice, Logoff
      res = http_send_recv3(
              method:"GET", 
              item:"/logoff.php", 
              port:port,
              exit_on_fail:TRUE
             ); 
    }
  }
  if (info && !thorough_tests) break;
}

install_url = build_url(port:port, qs:url);
if(info)
{
  if(report_verbosity > 0 )
  {
    if (max_index(split(info)) > 3) s = "s";
    else s = "";

    report =
      '\n' +
      'Nessus could log into the web management console using the \n' +
      'following set' + s + ' of credentials :\n' +
      '\n' +
      '  URL      : '+ install_url + '\n' +
      info;
     security_hole(port:port,extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Artica", install_url);
