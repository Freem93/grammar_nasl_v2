#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66361);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/20 14:21:42 $");

  script_cve_id("CVE-2013-1362");
  script_bugtraq_id(58142);
  script_osvdb_id(90582);
  script_xref(name:"EDB-ID", value:"24955");

  script_name(english:"Nagios NRPE nrpe.c Arbitrary Command Execution");
  script_summary(english:"Checks the version of the remote Nagios NRPE");

  script_set_attribute(attribute:"synopsis", value:
"The monitoring service running on the remote host is affected by an
arbitrary command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Nagios NRPE that contains a
flaw that is triggered when input passed via '$()' is not properly
sanitized before being used to execute plugins.

An unauthenticated, remote attacker could exploit this issue to
execute arbitrary commands within the context of the vulnerable
application.");
# http://www.occamsec.com/vulnerabilities.html#nagios_metacharacter_vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f72b1d9b");
  script_set_attribute(attribute:"solution", value:"Upgrade to Nagios NRPE 2.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nagios Remote Plugin Executor Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("nagios_nrpe_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/nrpe");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"nrpe", exit_on_fail:TRUE);

appname = "Nagios NRPE";

version = get_kb_item_or_exit("nrpe/" + port + "/Version");
if (version == 'unknown') audit(AUDIT_SERVICE_VER_FAIL, appname, port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = '2.14';
if (
  version =~ "^1\." ||
  version =~ "^2\.[0-9]($|[^0-9])" ||
  version =~ "^2\.1[0-3]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port,extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, appname, port, version);
