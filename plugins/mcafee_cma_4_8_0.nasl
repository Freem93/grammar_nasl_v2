#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70397);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id("CVE-2013-3627");
  script_bugtraq_id(62785);
  script_osvdb_id(98050);
  script_xref(name:"CERT", value:"613886");
  script_xref(name:"MCAFEE-SB", value:"SB10055");

  script_name(english:"McAfee Managed Agent FrameworkService.exe HTTP Request DoS (SB10055)");
  script_summary(english:"Checks the version of McAfee Framework Service.");

  script_set_attribute(attribute:"synopsis", value:
"A security management service running on the remote host is affected
by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the McAfee Managed Agent (MA)
running on the remote host is affected by denial of service
vulnerability in FrameworkService.exe due to a flaw when handling
malformed HTTP requests. An unauthenticated, remote attacker can
exploit this, via a specially crafted request, to cause the Framework
Service to crash.");
  script_set_attribute(attribute:"see_also", value:"http://kc.mcafee.com/corporate/index?page=content&id=SB10055");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patches according to the vendor's advisory.
Alternatively, as a workaround, it is possible to partially mitigate
the vulnerability by adjusting the Agent policy to only allow
connections from the ePO server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:mcafee_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_cma_detect.nasl");
  script_require_ports("Services/www", 8081);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "McAfee Agent";
port = get_http_port(default:8081, embedded: 1);

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
ver = install['version'];

ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);
update = int(ver_fields[3]);

fix = '';

# fixed in 4.8.0
# hotfixes for 4.5.x and 4.6.x
if (major < 4 || (major == 4 && minor < 5))
  fix = '4.8.0';

if (major == 4 && minor == 5 && rev == 0 && update < 1927)
  fix = '4.5.0.1927';

if (major == 4 && minor == 6 && rev == 0 && update < 3258)
  fix = '4.6.0.3258';

if (fix != '')
{
  report =
    '\n  Installed Version : ' + ver +
    '\n  Fixed Version     : ' + fix + '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "McAfee Common Management Agent", port, ver);
