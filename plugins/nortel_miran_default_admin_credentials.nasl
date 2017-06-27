#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72665);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_name(english:"Nortel Meridian Integrated RAN Default Admin Credentials");
  script_summary(english:"Tries to log into the remote host");

  script_set_attribute(attribute:"synopsis", value:"The remote system can be accessed with default credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote device is a Nortel Meridian Integrated RAN (MIRAN) that uses
a set of known, default credentials ('admin' / 'admin000').  Knowing
these, an attacker able to connect to the service can gain complete
control of the device. 

Nortel MIRAN is a system card that provides multi-tasking voice
processing applications such as Recorded Announcement (RAN) and
Music-On-Hold (MOH)."
  );
  script_set_attribute(attribute:"solution", value:"Log into the remote host and change the default login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("account_check.nasl", "telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include("audit.inc");
include("default_account.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

res = _check_telnet(
  port            : port,
  login           : 'admin' + '\r' + 'admin000' + '\r\r',
  password        : "", 
  login_regex     : "Username",
  cmd             : '3', 
  cmd_regex       : "\[Admin\].+System Information"
);

if (res) security_hole(port);
else audit(AUDIT_HOST_NOT, "affected");
