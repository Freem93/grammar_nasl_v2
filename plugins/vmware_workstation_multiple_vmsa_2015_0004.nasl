#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84223);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
    "CVE-2012-0897",
    "CVE-2015-2336",
    "CVE-2015-2337",
    "CVE-2015-2338",
    "CVE-2015-2339",
    "CVE-2015-2340"
  );
  script_bugtraq_id(51426, 75092, 75095);
  script_osvdb_id(
    78333,
    123089,
    123090,
    123091,
    123092,
    123093
  );
  script_xref(name:"VMSA", value:"2015-0004");

  script_name(english:"VMware Workstation 10.x < 10.0.6 / 11.x < 11.1.1 Multiple Vulnerabilities (VMSA-2015-0004) (Windows)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Windows host
is 10.x prior to 10.0.6 or 11.x prior to 11.1.1. It is, therefore,
affected by multiple vulnerabilities :

  - An arbitrary code execution vulnerability exists due to
    a stack-based buffer overflow condition in the JPEG2000
    plugin that is triggered when parsing a Quantization
    Default (QCD) marker segment in a JPEG2000 (JP2) image
    file. A remote attacker can exploit this, using a
    specially crafted image, to execute arbitrary code or
    cause a denial of service condition. (CVE-2012-0897)

  - Multiple unspecified remote code execution
    vulnerabilities exists in 'TPView.dll' and 'TPInt.dll'
    library files. (CVE-2015-2336, CVE-2015-2337)

  - The 'TPview.dll' and 'TPInt.dll' library files fail to
    properly handle memory allocation. A remote attacker can
    exploit this to cause a denial of service.
    (CVE-2015-2338, CVE-2015-2339, CVE-2015-2340)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2015-0004.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Workstation version 10.0.6 / 11.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Irfanview JPEG2000 jp2 Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/Workstation/Version", "VMware/Workstation/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'VMware Workstation';

version = get_kb_item("VMware/Workstation/Version");
if (isnull(version)) audit(AUDIT_NOT_INST, appname);

path = get_kb_item_or_exit("VMware/Workstation/Path");

fix  = NULL;
if (version =~ "^10\." && ver_compare(ver:version, fix:"10.0.6", strict:FALSE) == -1)
  fix = "10.0.6";
else if (version =~ "^11\." && ver_compare(ver:version, fix:"11.1.1", strict:FALSE) == -1)
  fix = "11.1.1";

if(fix)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity >0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
