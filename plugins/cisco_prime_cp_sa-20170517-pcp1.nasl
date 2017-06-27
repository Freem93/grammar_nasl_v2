#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100323);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/26 15:50:24 $");

  script_cve_id(
    "CVE-2017-6621",
    "CVE-2017-6622",
    "CVE-2017-6635"
  );
  script_bugtraq_id(
    98520,
    98522,
    98535
  );
  script_osvdb_id(
    157718,
    157724,
    157726
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc98724");
  script_xref(name:"IAVA", value:"2017-A-0155");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc99626");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc99597");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170517-pcp1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170517-pcp2");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170517-pcp3");

  script_name(english:"Cisco Prime Collaboration Provisioning < 12.1 Multiple Vulnerabilities (cisco-sa-20170517-pcp1 - cisco-sa-20170517-pcp3)");
  script_summary(english:"Checks the Cisco Prime Collaboration Provisioning version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote network management server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Cisco Prime
Collaboration Provisioning server is 9.x, 10.x, 11.x, or 12.x prior to
12.1. It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    web interface when handling HTTP requests. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to disclose sensitive
    information about the application, such as user
    credentials. (CVE-2017-6621)

  - An authentication bypass vulnerability exists in the web
    interface due to missing security restraints in certain
    HTTP request methods that could allow accessing files.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted HTTP request, to bypass
    authentication and execute arbitrary commands with root
    privileges. (CVE-2017-6622)

  - A flaw exists in the web interface that allows directory
    traversal outside of a restricted path due to improper
    validation of HTTP requests and a failure to apply
    role-based access controls (RBACs) to requested HTTP
    URLs. An authenticated, remote attacker can exploit
    this, via a specially crafted request that uses path
    traversal, to delete arbitrary files from the system.
    (CVE-2017-6635)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170517-pcp1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e00b5d5b");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170517-pcp2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d26be4e8");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170517-pcp3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34619a9c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Collaboration Provisioning version 12.1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_provisioning");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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
if (version =~ "^(9|1[0-2])$")
  audit(AUDIT_VER_NOT_GRANULAR, appname, version);

fix = "12.1.0";

# 9.x - 12.x
if(version =~ "^(9|1[0-2])\." &&
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
