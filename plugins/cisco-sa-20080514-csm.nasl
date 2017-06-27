#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70137);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/15 16:37:15 $");

  script_cve_id("CVE-2008-1749");
  script_bugtraq_id(29216);
  script_osvdb_id(45201);

  script_name(english:"Cisco Content Switching Module Layer 7 Load Balancing DoS");
  script_summary(english:"Checks CSM version");

  script_set_attribute(attribute:"synopsis", value:
"The remote switch contains a switching module with a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco Content
Switching Module in the remote switch may be affected by a denial of
service vulnerability. 

The vulnerability exists when the CSM or CSM-S is configured for layer 7
load balancing.  An attacker can trigger this vulnerability when the CSM
or CSM-S processes TCP segments with a specific combination of TCP flags
while servers behind the CSM/CSM-S are overloaded and/or fail to accept
a TCP connection. 

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number. Additionally,
the vulnerability only affects Content Switching Modules configured
for layer 7 load balancing.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20080514-csm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e333797");
  script_set_attribute(attribute:"solution", value:
"Cisco has released free software updates that address this
vulnerability.  Prior to deploying software, customers should consult
their maintenance provider or check the software for feature set
compatibility and known issues specific to their environment.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:cisco_content_switching_module");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_csmsw_version.nasl");
  script_require_keys("Host/Cisco/CSMSW/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb = "Host/Cisco/CSMSW";
mod = get_kb_item_or_exit(kb + "/Module");
ver = get_kb_item_or_exit(kb + "/Version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Determine if the CSM/-S is vulnerable
# CSM: 4.2(3), 4.2(3a), 4.2(4), 4.2(5), 4.2(6), 4.2(7), and 4.2(8)
# CSM-S: 2.1(2), 2.1(3), 2.1(4), 2.1(5), 2.1(6), and 2.1(7)
fix = null;
if (mod == "WS-X6066-SLB-APC")
{
  if (ver =~ "^4\.2\(([3-8][a-z]*)\)$")
    fix = "4.2.9";
}
else if (mod == "WS-X6066-SLB-S-K9")
{
  if (ver =~ "^2\.1\([2-7][a-z]*\)$")
    fix = "2.1.8";
}

if (isnull(fix)) audit(AUDIT_INST_VER_NOT_VULN, "Cisco Content Switching Module " + mod, ver);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Module            : ' + mod +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}
security_hole(port:0, extra:report);
