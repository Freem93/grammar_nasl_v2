#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36075);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/17 21:38:53 $");

  script_cve_id("CVE-2008-6680", "CVE-2009-1241", "CVE-2009-1270");
  script_bugtraq_id(34344, 34357);
  script_osvdb_id(53461, 53597, 53598, 53599);

  script_name(english:"ClamAV < 0.95 Scan Evasion");
  script_summary(english:"Sends a VERSION command to clamd");

  script_set_attribute(attribute:"synopsis", value:"The remote antivirus service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the clamd antivirus daemon on the remote
host is earlier than 0.95. Such versions are affected by multiple
vulnerabilities :

  - A failure to handle certain malformed 'RAR' archive
    files could make it possible for certain archive files
    to
    evade detection from the scan engine. (Bug 1467)

  - A failure to handle certain malformed 'RAR' archive
    files could send the application into an infinite loop,
    which could make it possible to crash the scan engine.
    (Bug 1462)

  - A divide by zero issue when handling specially crafted
    'PE' file could be used to crash the affected
    application. (Bug 1335)");
  # http://blog.zoller.lu/2009/04/clamav-094-and-below-evasion-and-bypass.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e1b5afc");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Apr/20");
  # http://web.archive.org/web/20080723153709/http://svn.clamav.net/svn/clamav-devel/trunk/ChangeLog
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91209430");
  script_set_attribute(attribute:"solution", value:"Upgrade to ClamAV 0.95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94, 189);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

if (version =~ "^0\.(([0-9]|[0-8][0-9]|9[0-4])($|[^0-9]))")
{
  if (report_verbosity > 0)
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
