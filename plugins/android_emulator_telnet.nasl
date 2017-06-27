#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66381);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_name(english:"Android Emulator Telnet Port on Remote Host");
  script_summary(english:"Detects the Telnet port of an Android emulator.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host exposes the Telnet control port of an Android
emulator.");
  script_set_attribute(attribute:"description", value:
"The remote host exposes the Telnet control port of an Android emulator
allowing full, unauthenticated control of the emulator software
instance.");
  script_set_attribute(attribute:"solution", value:
"Configure the firewall to prevent access to this port or configure the
emulator software to listen on local interfaces only.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  # https://sites.google.com/site/androidhowto/how-to-1/connect-send-commands-to-your-android-emulator
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0f1ed78");


  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/11");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 5554);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Checks if the target host is the loopback interface. IPv6 and IPv4
# compatible.
function isloopbackint()
{
  local_var ip;
  ip = get_host_ip();
  return (ip == "::1" || ip =~ "^127\.");
}

if (isloopbackint())
  exit(0, "Not scanning the loopback interface.");

port = get_service(svc:'android_emulator_telnet', exit_on_fail:TRUE);

if (port)
  security_hole(port);
else
  audit(AUDIT_NOT_DETECT, "An Android emulator Telnet control port", port);
