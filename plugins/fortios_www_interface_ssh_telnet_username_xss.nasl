#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85742);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/03 13:42:46 $");

  script_osvdb_id(125008);

  script_name(english:"Fortinet FortiOS 5.0.x < 5.0.9 Telnet / SSH Username XSS");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:"
The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Fortinet FortiOS 5.0.x prior
to 5.0.9. It is, therefore, affected by a cross-site scripting
vulnerability due to improper validation of user-supplied input to the
Telnet and SSH usernames. An unauthenticated, remote attacker can
exploit this vulnerability to execute arbitrary script code in the
context of the current user.");
  # http://kb.fortinet.com/kb/microsites/search.do?cmd=displayKC&docType=kc&externalId=fortios-v509-release-notespdf
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?f14b2f76");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS 5.0.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiOS";
model    = get_kb_item_or_exit("Host/Fortigate/model");
version  = get_kb_item_or_exit("Host/Fortigate/version");

if (version =~ "^5(\.0)?$") audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

if (version =~ "^5\.0\.[0-8]($|[^0-9])")
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.0.9' +
      '\n';
    security_warning(extra:report, port:0);
  }
  else security_warning(port:0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
