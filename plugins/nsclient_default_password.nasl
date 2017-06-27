#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40330);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_name(english:"NSClient Default Password");
  script_summary(english:"Tries to access NSClient with the default password");

  script_set_attribute(attribute:"synopsis", value:"The remote monitoring agent is configured with a default password.");
  script_set_attribute( attribute:"description", value:
"The remote host is running an instance of NSClient, an addon for Nagios
used to monitor Windows hosts, configured using a default password. 
Anyone can connect to it and retrieve sensitive information, such as
process and service states, memory usage, etc.");
  script_set_attribute(attribute:"solution", value:"Configure the remote instance of NSClient to use a different password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/pNSClient", 1248);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"pNSClient", default:1248, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

pass = "None";

req = string(pass, "&1");
send(socket:soc, data:req);
res = recv(socket:soc, length:256, min:4);
close(soc);

if (!strlen(res)) exit(0, "No response received.");
if ('ERROR:Wrong password' == res) exit(0, "The NSClient install is not affected.");

if (ereg(pattern:'^[0-9]+\\.[0-9]+\\.', string:res))
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to identify the version of the remote NSClient install\n",
      "as '", res, "' by sending it the request '", req, "', where '", pass, "' is the\n",
      "default password.\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(1, "Received an unexpected response ("+res+").");
