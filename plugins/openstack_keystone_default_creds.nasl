#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62354);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_name(english:"OpenStack Keystone Default Credentials");
  script_summary(english:"Tries to access the portal with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the remote OpenStack Keystone instance by
providing default credentials.  Knowing these, an attacker can gain
administrative control of the affected application and would then be
able to read and write to Keystone, which is used as an identity
provider by other services.");
  script_set_attribute(attribute:"see_also", value:"https://launchpad.net/keystone");
  # https://raw.github.com/openstack/keystone/master/etc/keystone.conf.sample
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?350f4002");
  script_set_attribute(attribute:"solution", value:"Change the credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openstack:keystone");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("openstack_keystone_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/openstack_keystone");
  script_require_ports("Services/www", 35357);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("json.inc");
include("misc_func.inc");
include("path.inc");
include("webapp_func.inc");

app = "OpenStack Keystone";

# Get the ports that webservers have been found on, defaulting to
# the admin port.
port = get_kb_item("Services/www");
if (isnull(port))
{
  port = 35357;
  if (!service_is_unknown(port:port)) exit(0, "The service on port " + port + " has been previously identified.");
}
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Get details of the install.
name = "openstack_keystone";
install = get_install_from_kb(appname:name, port:port, exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install["dir"];
path = dir + "/v2.0/users";

# This only works against the admin API.
get_kb_item_or_exit("www/"+port+"/"+name+"/admin");

# Request the list of users.
token = "ADMIN";
hdrs = make_array("x-auth-token", token);

res = http_send_recv3(
  port            : port,
  method          : "GET",
  item            : path,
  add_headers     : hdrs,
  exit_on_fail    : TRUE
);
if (max_index(res) <= 2) exit(1, "The "+app+" service listening on port "+port+" did not return an HTTP response body as expected.");

# Check if we got the list of users.
json = json_read(res[2]);
if (
  isnull(json) ||
  isnull(json[1]) ||
  isnull(json[0]) ||
  isnull(json[0]["users"]) ||
  !is_list(json[0]["users"])
) exit(0, "Failed to log into " + app + " with default credentials on port " + port + ".");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  header = 'Nessus was able to gain access using the following URL';
  trailer =
    'The following credentials were used :' +
    '\n' +
    '\n  Authentication Token : ' + token;

  if (report_verbosity > 1)
  {
    users = make_list();
    foreach user (json[0]["users"])
    {
      if (typeof(user) != "array")
        continue;

      name = user["name"];
      if(!isnull(name))
        users = make_list(users, name);
    }

    if (max_index(users) > 0)
    {
      trailer +=
        '\n' +
        '\nThe following users were returned by our request :' +
        '\n' +
        '\n  ' + join(sort(users), sep:'\n  ');
    }
  }

  report = get_vuln_report(items:path, port:port, header:header, trailer:trailer);
}

security_hole(port:port, extra:report);
