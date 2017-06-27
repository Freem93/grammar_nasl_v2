#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35009);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/05/25 02:11:20 $");

  script_cve_id("CVE-2008-5314");
  script_bugtraq_id(32555);
  script_osvdb_id(50363);
  script_xref(name:"Secunia", value:"32926");

  script_name(english:"ClamAV < 0.94.2 cli_check_jpeg_exploit() Malformed JPEG File DoS");
  script_summary(english:"Sends a VERSION command to clamd");

  script_set_attribute(attribute:"synopsis", value:
"The remote antivirus service is vulnerable to a denial of service
attack.");
  script_set_attribute(attribute:"description", value:
"According to its version, the clamd antivirus daemon on the remote
host is earlier than 0.94.2. There is a recursive stack overflow
involving the JPEG parsing code in such versions. A remote attacker
may be able to leverage this issue to cause the application to
recursively scan a specially crafted JPEG, which will eventually cause
it to crash.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.clamav.net/show_bug.cgi?id=1266");
  # http://web.archive.org/web/20080723153709/http://svn.clamav.net/svn/clamav-devel/trunk/ChangeLog
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91209430"); # look for bb#1266
  script_set_attribute(attribute:"solution", value:"Upgrade to ClamAV 0.94.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/clamd", 3310);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");


# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_kb_item("Services/clamd");
if (!port) port = 3310;
if (!get_port_state(port)) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a VERSION command.
req = "VERSION";
send(socket:soc, data:req+'\r\n');

res = recv_line(socket:soc, length:128);
if (!strlen(res) || "ClamAV " >!< res) exit(0);


# Check the version.
version = strstr(res, "ClamAV ") - "ClamAV ";
if ("/" >< version) version = version - strstr(version, "/");

if (version =~ "^0\.(([0-9]|[0-8][0-9]|9[0-3])($|[^0-9])|94(\.1)?($|[^0-9.]))")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "ClamAV version ", version, " appears to be running on the remote host based on\n",
      "the following response to a 'VERSION' command :\n",
      "\n",
      "  ", res, "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
