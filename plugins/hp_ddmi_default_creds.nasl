#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39616);
  script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_name(english:"HP DDMI Web Interface Default Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application is protected using default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote host is running HP Discovery & Dependency Mapping Inventory
(DDMI), which is used to automate discovery and inventory of network
devices. 

The remote installation of HP DDMI has at least one account configured
using default credentials.  Knowing these, an attacker can gain access
to the affected application, possibly even as an administrator.");
  script_set_attribute(attribute:"solution", value:"Change the password of any reported user.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:hp:discovery%26dependency_mapping_inventory");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Make sure it's DDM Inventory.
res = http_get_cache(item:"/", port:port, exit_on_fail: TRUE);

if (
  "title>HP Discovery and Dependency Mapping Inventory</title>" >!< res &&
  '<span class="loginTitle">HP Discovery and Dependency Mapping Inventory' >!< res
) audit(AUDIT_WEB_APP_NOT_INST, "HP Discovery & Dependency Mapping Inventory (DDMI)", port);


# Try to log in.
n = 0;
creds = make_array();

users[n] = "admin";
passes[n] = "password";
n++;

users[n] = "itmanager";
passes[n] = "password";
n++;

users[n] = "itemployee";
passes[n] = "password";
n++;

users[n] = "demo";
passes[n] = "password";
n++;



# Pull up the login form.
info = "";
url = "/nm/webui/";

for (i=0; i<n; i++)
{
  user = users[i];
  pass = passes[i];

  init_cookiejar();

  req = http_mk_get_req(
    port        : port,
    item        : url,
    add_headers : make_array(
      'Authorization',
      ('Basic ' + base64(str:user+":"+pass))
    )
  );
  res = http_send_recv_req(port:port, req:req, exit_on_fail: TRUE);

  # There's a problem if we've bypassed authentication.
  if ('content="0;url=/webui/customAuth.jsp"' >< res[2])
  {
    info +=
      '\n' +
      '  Username : ' + user + '\n' +
      '  Password : ' + pass + '\n';
    if (!thorough_tests) break;
  }
}

install_url =  build_url(port:port, qs:url);
if (info)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to gain access using the following information :\n' +
      '\n' +
      '  URL      : ' + install_url + '\n' +
      # nb: info already has a leading newline
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "HP Discovery & Dependency Mapping Inventory (DDMI)", install_url);
