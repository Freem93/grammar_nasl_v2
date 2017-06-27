#
# (C) Tenable Network Security, Inc.
#
# Ref:
#  From: "Paul Craig" <pimp@brainwave.net.nz>
#  To: <bugtraq@securityfocus.com>
#  Subject: ImageFolio All Versions      (...)
#  Date: Thu, 5 Jun 2003 13:53:57 +1200

include("compat.inc");

if (description)
{
 script_id(11700);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");

 script_xref(name:"Secunia", value:"8964");

 script_name(english:"ImageFolio Default Password");
 script_summary(english:"Logs in as Admin/ImageFolio");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a web application that uses a default
administrator password.");
 script_set_attribute(attribute:"description", value:
"The remote host is running the ImageFolio image gallery manager. 

This CGI is installed with a default administrator username and password
(Admin/ImageFolio) that has not been modifed. 

An attacker could exploit this flaw to administrate this installation. 

In addition to this, the CGI admin.cgi has a bug that could allow an
attacker to delete arbitrary files owned by the remote web server.");
 script_set_attribute(attribute:"see_also", value:"http://secunia.com//advisories/8964/");
 script_set_attribute(attribute:"solution", value:"Set a strong password for the administrator account.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/05");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_exclude_keys("global_settings/supplied_logins_only", "Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

function check(req)
{
  local_var res;
  local_var variables;

  variables = string("login=1&user=Admin&password=ImageFolio&save=Login");
  res = http_send_recv3(method:"POST",
                        item:req,
                        add_headers:make_array(
                                    "Content-Type", "application/x-www-form-urlencoded",
                                    "Content-Length", strlen(variables)),
                        data:variables,
                        port:port,
                        exit_on_fail:TRUE);

  if ("<title>My ImageFolio Gallery Administration : </title>" >< res[2])
  {
    security_hole(port);
    exit(0);
  }
  return (0);
}

foreach dir (cgi_dirs())
{
 check(req:dir + "/admin/admin.cgi");
}
exit(0, "The web server listening on port "+port+" is not affected.");
