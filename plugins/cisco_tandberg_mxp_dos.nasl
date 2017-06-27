#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69825);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_bugtraq_id(42827);
  script_osvdb_id(67770);
  script_xref(name:"IAVB", value:"2010-B-0086");

  script_name(english:"Cisco TANDBERG MXP < 9.0 SNMP Packet Handling DoS");
  script_summary(english:"Checks TANDBERG version via the telnet banner");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application on the remote host is affected by a denial of service
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running TANDBERG MXP Endpoint, an application used
for video conferencing. 

According to the version number identified in the telnet banner, the
TANDBERG MXP Endpoint version running on the remote host is less than
F9.0.  As such, the install is potentially affected by a remote denial
of service condition as the firmware incorrectly processes Simple
Network Management Protocol (SNMP) packets.  A remote, unauthenticated
attacker could exploit this issue by sending a specially crafted SNMP
packet to the affected device causing a denial of service (DoS)
condition. 

Note that Nessus did not test for this issue, but rather relied on the
application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Aug/381");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=21335");
  # http://www.cisco.com/en/US/docs/telepresence/endpoint/software/mxp/f9/release_notes/mxp_endpoints_software_release_notes_f9.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c78aa44");
  script_set_attribute(attribute:"solution", value:"Upgrade to version F9.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:tandberg_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_require_ports("Services/telnet", 23);
  exit(0);
}

include("audit.inc");
include("telnet_func.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);
app = 'Cisco TANDBERG';

banner = get_telnet_banner(port:port);
if (!banner) audit(AUDIT_NO_BANNER, port);

version = NULL;
if ("tandberg codec" >< tolower(banner))
{
  match = eregmatch(pattern:"Release ([A-Z][0-9.]+)", string:banner);
  if (!isnull(match)) version = match[1];
}
else audit(AUDIT_NOT_DETECT, app, port);

if (isnull(version)) exit(1, "Failed to determine the version of the " +app+ " Endpoint identified on port " +port+ ".");

# Check Version
if (version =~ "^F(7\.[0234]|8\.[0-2])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    match = eregmatch(
      pattern : "(tandberg codec release .*)",
      string  : banner,
      icase   : TRUE
    );
    if (!isnull(match)) source = match[1];
    else source = banner;

    report =
      '\n  Source            : ' +source+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : F9.0\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The " +app+ " Endpoint identified on port " +port+ " is running software version " + version + " and thus is not affected.");
