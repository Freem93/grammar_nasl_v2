#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69948);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/24 13:12:21 $");

  script_cve_id("CVE-2012-0329");
  script_bugtraq_id(51537);
  script_osvdb_id(78336);
  script_xref(name:"CISCO-BUG-ID", value:"CSCts63878");
  script_xref(name:"IAVB", value:"2012-B-0010");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120118-dmm");

  script_name(english:"Cisco Digital Media Manager < 5.3 Privilege Escalation");
  script_summary(english:"Obtains the version of the Cisco Digital Media Manager");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote device is running a version of Cisco Digital Media Manager
prior to 5.3.  As such, it is affected by a privilege escalation
vulnerability.  A remote, authenticated attacker could leverage this to
execute arbitrary code on the device.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120118-dmm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10d82ddc");
  script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/id/1026541");
  script_set_attribute(attribute:"solution", value:"Update to Cisco Digital Media Manager version 5.3 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:digital_media_manager");

  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();
  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"SNMP");

  script_dependencies("snmp_sysDesc.nasl");
  script_require_keys("SNMP/community");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("snmp_func.inc");

community = get_kb_item_or_exit("SNMP/community");

port = get_kb_item("SNMP/port");
if (!port) port = 161;
if (!get_udp_port_state(port))  audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (isnull(soc)) audit(AUDIT_SOCK_FAIL, port, "UDP");

major = snmp_request(socket:soc, community:community, oid:"1.3.6.1.4.1.9.9.655.1.1.1");
minor = snmp_request(socket:soc, community:community, oid:"1.3.6.1.4.1.9.9.655.1.1.2");
patch = snmp_request(socket:soc, community:community, oid:"1.3.6.1.4.1.9.9.655.1.1.3");

if (isnull(major)) audit(AUDIT_NOT_DETECT, "Cisco Digital Media Manager");
if (isnull(minor)) minor = "0";
if (isnull(patch)) patch = "0";

version = major + "." + minor + "." + patch;
fixed = "5.3";

if (ver_compare(ver:version, fix:fixed, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
  exit(0);
}

audit(AUDIT_INST_VER_NOT_VULN, "Cisco Digital Media Manager", version);
