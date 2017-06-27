#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93400);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2016-1320");
  script_bugtraq_id(83137);
  script_osvdb_id(134346);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux69286");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160209-pcp");

  script_name(english:"Cisco Prime Collaboration Provisioning 9.0.x / 11.0.x < 11.1 Local Privilege Escalation (cisco-sa-20160209-pcp)");
  script_summary(english:"Checks the Cisco Prime Collaboration Provisioning version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote network management server is affected by a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Cisco Prime
Collaboration Provisioning server is 9.0.x or 11.0.x prior to 11.1. It
is, therefore, affected by a local privilege escalation vulnerability
in its command line interface due to improper sanitization of
user-supplied input. A local attacker with administrator-level access
can exploit this to gain root access to the host operating system.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160209-pcp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1574c1f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Collaboration Provisioning version 11.1.0 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_provisioning");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_prime_collaboration_provisioning_detect.nbin");
  script_require_keys("Host/Cisco/PrimeCollaborationProvisioning/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Prime Collaboration Provisioning";
version = get_kb_item_or_exit("Host/Cisco/PrimeCollaborationProvisioning/version");

# We got the version from the WebUI and its not granular enough
if (version == "9" || version == "11")
  audit(AUDIT_VER_NOT_GRANULAR, appname, version);

fix = "11.1.0";

if(
  version =~ "^(9\.0|11\.0)([^0-9]|$)" &&
  ver_compare(ver:version, fix:fix, strict:FALSE) < 0
)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
