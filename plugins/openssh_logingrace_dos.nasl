#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67140);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/24 02:15:10 $");

  script_cve_id("CVE-2010-5107");
  script_bugtraq_id(58162);
  script_osvdb_id(90007);

  script_name(english:"OpenSSH LoginGraceTime / MaxStartups DoS");
  script_summary(english:"Checks OpenSSH banner version");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is susceptible to a remote denial of service
attack.");
  script_set_attribute(attribute:"description", value:
"According to its banner, a version of OpenSSH earlier than version 6.2
is listening on this port.  The default configuration of OpenSSH
installs before 6.2 could allow a remote attacker to bypass the
LoginGraceTime and MaxStartups thresholds by periodically making a large
number of new TCP connections and thereby prevent legitimate users from
gaining access to the service. 

Note that this plugin has not tried to exploit the issue or detect
whether the remote service uses a vulnerable configuration.  Instead, it
has simply checked the version of OpenSSH running on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2013/02/06/5");
  script_set_attribute(attribute:"see_also", value:"http://openssh.org/txt/release-6.2");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=28883");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 6.2 and review the associated server configuration
settings.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:'ssh', exit_on_fail:TRUE);

# Get banner for service
banner = get_kb_item_or_exit("SSH/banner/"+port);

if ("openssh" >!< tolower(banner)) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) audit(AUDIT_BACKPORT_SERVICE, 22, "OpenSSH");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

match = eregmatch(string:tolower(banner), pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) exit(1, "Could not parse the version string in the banner from port "+port+".");
version = match[1];


if (
  version =~ "^[0-5]\." ||
  version =~ "^6\.[0-1]($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.2' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "OpenSSH", port, version);
