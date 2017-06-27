#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(11600);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_name(english:"NetCharts Server Default Password");
  script_summary(english:"NetCharts Server Default Password");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service has a well known, default password.'
  );
  script_set_attribute(
    attribute:'description',
    value:
"The remote host is running the NetCharts server on this port, with the
default login and password of 'Admin/Admin'. 

An attacker may use this misconfiguration to control the remote server."
  );
  script_set_attribute(
    attribute:'solution',
    value:"Change the password of the 'Admin' account to a stronger one."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:visual_mining:netcharts_xbrl_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 8001);

  exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8001);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

w = http_send_recv3(method: "GET", item: "/Admin/index.jsp", port: port,
  username: "Admin", password: "Admin", exit_on_fail:TRUE);
res = strcat(w[0], w[1], '\r\n', w[2]);
if (w[0] =~ "^HTTP.* 200 " && "NetCharts Server" >< res)
 security_hole(port);
else audit(AUDIT_HOST_NOT, "affected");
