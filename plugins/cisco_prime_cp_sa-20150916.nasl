#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86192);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/26 15:50:24 $");

  script_cve_id("CVE-2015-4307");
  script_bugtraq_id(76760);
  script_osvdb_id(127647);
  script_xref(name:"CISCO-BUG-ID", value:"CSCut64111");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150916-pcp");

  script_name(english:"Cisco Prime Collaboration Provisioning Web Framework Access Controls Bypass Vulnerability (cisco-sa-20150916-pcp)");
  script_summary(english:"Checks the Cisco Prime Collaboration Provisioning version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote network management device is affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco Prime
Collaboration Provisioning device is a version prior to 11.0.0.650. It
is, therefore, affected by a security bypass vulnerability in the web
framework due to improper implementation of authorization and access
controls. An authenticated, remote attacker can exploit this, via a
crafted URL request, to access higher-privileged functions that are
normally restricted to administrative users only.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150916-pcp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a696954e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Collaboration Provisioning version 11.0.0.650.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_provisioning");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_prime_collaboration_provisioning_detect.nbin");
  script_require_keys("Host/Cisco/PrimeCollaborationProvisioning/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Prime Collaboration Provisioning";
version = get_kb_item_or_exit("Host/Cisco/PrimeCollaborationProvisioning/version");

# The advisory says this vulnerability has been resolved in 
# Cisco Prime Collaboration Provisioning Software Release 
# 11.0.0.650 and later.

fix = '11.0.0.650';

if(ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
