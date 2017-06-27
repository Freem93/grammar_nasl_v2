#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23731);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/18 21:06:04 $");

  script_name(english:"HSQLDB Server Default Credentials");
  script_summary(english:"Checks for default credentials with an HSQLDB server");

  script_set_attribute(attribute:"synopsis", value:"The remote database service is using default credentials.");
  script_set_attribute(attribute:"description", value:
"The installation of HSQLDB on the remote host has the default 'sa'
account enabled without a password.  An attacker may use this flaw to
execute commands against the remote host, as well as read any data it
might contain.");
  script_set_attribute(attribute:"solution", value:
"Disable this account or assign a password to it.  In addition, it is
suggested that you filter incoming traffic to this port.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies ("hsqldb_detect.nasl");
  script_require_ports("Services/hsqldb", 9001);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"hsqldb", default:9001, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);


# Try to login with default credentials.
user = toupper("sa");                   # default username
pass = toupper("");                     # default password
db = "";

req = raw_string(
                                        # packet size, to be added later
  0x00, 0x01, 0x00, 0x07,               # ???, perhaps a version number
  0x00, 0x00, 0x00, 0x00,               # ???
  0x00, 0x00, 0x00, 0x00,               # ???
  0x00, 0x00, 0x00, strlen(user), user, # user
  0x00, 0x00, 0x00, strlen(pass), pass, # pass
  0x00, 0x00, 0x00, strlen(db), db,     # database name
  0x00, 0x00, 0x00, 0x00                # ???
);
req = raw_string(
  0x00, 0x00, 0x00, (strlen(req)+4),    # packet size, as promised
  req
);
send(socket:soc, data:req);
res = recv(socket:soc, length:64);
if (res == NULL) exit(0);


# There's a problem if we were able to authenticate.
if (
  strlen(res) == 20 &&
  raw_string(
    0x00, 0x00, 0x00, 0x14,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00
  ) >< res
) security_hole(port);
else audit(AUDIT_LISTEN_NOT_VULN, 'HSQLDB', port);
