#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84150);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/04/28 13:38:34 $");

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
    123089,
    123090,
    123091,
    123092,
    123093
  );
  script_xref(name:"VMSA", value:"2015-0004");

  script_name(english:"VMware Horizon View Client 3.2.x < 3.2.1 / 3.3.x < 3.4.0 / or 5.x < 5.4.2 Multiple Vulnerabilities (VMSA-2015-0004)");
  script_summary(english:"Checks the VMware Horizon View Client version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtual desktop solution installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Horizon View Client installed on the remote host
is 3.2.x prior to 3.2.1, 3.3.x prior to 3.4.0, or 5.x (with local
mode) prior to 5.4.2. It is, therefore, affected by multiple
vulnerabilities :

  - An arbitrary code execution vulnerability exists due to
    a stack-based buffer overflow condition in the JPEG2000
    plugin that is triggered when parsing a Quantization
    Default (QCD) marker segment in a JPEG2000 (JP2) image
    file. A remote attacker can exploit this, using a
    specially crafted image, to execute arbitrary code or
    cause a denial of service condition. (CVE-2012-0897)

  - Multiple denial of service vulnerabilities exist due to
    improper memory allocation by the TPView.dll and
    TPInt.dll libraries. A remote attacker can exploit this
    to cause a denial of service condition. (CVE-2015-2338,
    CVE-2015-2339, CVE-2015-2340)

  - Multiple remote code execution vulnerabilities exist due
    to improper memory allocation by the TPView.dll and
    TPInt.dll libraries. A remote attacker can exploit this
    to execute arbitrary code. (CVE-2015-2336,
    CVE-2015-2337)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0004");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Horizon View Client 3.2.1 / 3.4.0 / 5.4.2 (with
local mode) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Irfanview JPEG2000 jp2 Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("vmware_horizon_view_client_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Horizon View Client");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'VMware Horizon View Client';

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);

version    = install["version"];
path       = install["path"];
local_mode = install["Local Mode"];

if (local_mode == "yes")
  appname += " (with local mode)";

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (version =~ "^3\.2(\.|$)")
  fix = "3.2.1";
else if (version =~ "^3\.3(\.|$)")
  fix = "3.4.0";
else if (version =~ "^5(\.|$)" && local_mode == "yes")
  fix = "5.4.2";
else
  audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Product           : ' + appname +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version+
    '\n  Fixed version     : ' + fix + '\n';
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

if (report_verbosity > 0) security_hole(port:port, extra:report);
else security_hole(port);
