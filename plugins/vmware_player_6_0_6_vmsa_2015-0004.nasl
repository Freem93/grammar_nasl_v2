#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84219);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id(
    "CVE-2012-0897",
    "CVE-2015-2336",
    "CVE-2015-2337",
    "CVE-2015-2338",
    "CVE-2015-2339",
    "CVE-2015-2340",
    "CVE-2015-2341"
  );
  script_bugtraq_id(
    51426,
    75092,
    75094,
    75095
  );
  script_osvdb_id(
    78333,
    123089,
    123090,
    123091,
    123092,
    123093,
    123094
  );
  script_xref(name:"VMSA", value:"2015-0004");

  script_name(english:"VMware Player 6.x < 6.0.6 Multiple Vulnerabilities (VMSA-2015-0004)");
  script_summary(english:"Checks the VMware Player version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Player installed on the remote Windows host is
6.x prior to 6.0.6. It is, therefore, affected by multiple
vulnerabilities :

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
    (CVE-2015-2338, CVE-2015-2339, CVE-2015-2340)

  - A denial of service vulnerability exists due to improper
    validation of user-supplied input to a remote procedure
    call (RPC) command. An unauthenticated, remote attacker
    can exploit this, via a crafted command, to crash the
    host or guest operating systems. (CVE-2015-2341)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2015-0004.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Player version 6.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Irfanview JPEG2000 jp2 Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_player_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/Player/Path", "VMware/Player/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

version = get_kb_item_or_exit("VMware/Player/Version");
path = get_kb_item_or_exit("VMware/Player/Path");

fixed = '6.0.6';
if (
  version =~ "^6\." &&
  ver_compare(ver:version, fix:fixed, strict:FALSE) == -1
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Player", version, path);
