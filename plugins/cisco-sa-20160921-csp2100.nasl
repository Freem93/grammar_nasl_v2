#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94054);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");
  
  script_cve_id("CVE-2016-6373", "CVE-2016-6374");
  script_bugtraq_id(93093, 93095);
  script_osvdb_id(144664, 144665);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz89093");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva00541");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160921-csp2100-1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160921-csp2100-2");
  script_xref(name:"IAVA", value:"2016-A-0267");

  script_name(english:"Cisco Cloud Services Platform 2.x < 2.1.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the Cisco Services Platform version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote network virtual services management device is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Cisco Cloud
Services Platform (CSP) device is 2.x prior to 2.1.0. It is,
therefore, affected by the following vulnerabilities :

  - A command injection vulnerability exists in the
    web-based GUI due to improper sanitization of
    user-supplied input. An authenticated, remote attacker
    can exploit this to execute arbitrary operating system
    commands with root privileges. (CVE-2016-6373)

  - A remote code execution vulnerability exists in the
    web-based GUI due to improper sanitization of
    user-supplied data from HTTP requests. An
    unauthenticated, remote attacker can exploit this, via a
    crafted dnslookup command in an HTTP request, to execute
    arbitrary code. (CVE-2016-6374)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160921-csp2100-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f34d1428");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160921-csp2100-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6eb17f5f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva00541");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz89093");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Cloud Services Platform version 2.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:cloud_services_platform_2100");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/CloudServicesPlatform/version", "Host/Cisco/CloudServicesPlatform/model");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Cisco Cloud Services Platform";
version = get_kb_item_or_exit("Host/Cisco/CloudServicesPlatform/version");
model   = get_kb_item_or_exit("Host/Cisco/CloudServicesPlatform/model");

if (model != "2100") audit(AUDIT_DEVICE_NOT_VULN, appname + ' ' + model);

fix = "2.1.0";

if(version =~ "^2\." && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_DEVICE_NOT_VULN, appname + ' ' + model, version);
