#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89108);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id("CVE-2012-1518");
  script_bugtraq_id(53006);
  script_osvdb_id(81163);
  script_xref(name:"VMSA", value:"2012-0007");

  script_name(english:"VMware ESX / ESXi Tools Folder Incorrect ACL Privilege Escalation  (VMSA-2012-0007) (remote check)");
  script_summary(english:"Checks the remote ESX/ESXi host's version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi / ESX host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote ESX/ESXi host is missing a security-related patch. It is,
therefore, affected by a privilege escalation vulnerability due to the
use of an incorrect Access Control List (ACL) for the VMware Tools
folder. An adjacent attacker can exploit this to gain elevated
privileges on Windows-based guest operating systems.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2012-0007.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");
  script_require_ports("Host/VMware/vsphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");
port = get_kb_item_or_exit("Host/VMware/vsphere");

esx = "ESX/ESXi";

extract = eregmatch(pattern:"^(ESXi?) (\d\.\d).*$", string:ver);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_APP_VER, esx);
else
{
  esx = extract[1];
  ver = extract[2];
}

product = "VMware " + esx;

# fix builds
fixes = make_array(
  "ESX 3.5",  604481,
  "ESXi 3.5", 604481,
  "ESX 4.0",  660575,
  "ESXi 4.0", 660575,
  "ESX 4.1",  582267,
  "ESXi 4.1", 582267,
  "ESXi 5.0", 623860
);

# security-only fix builds
sec_only_builds = make_array(
  "ESXi 5.0", 608089
);

key = esx + ' ' + ver;
fix = NULL;
fix = fixes[key];
sec_fix = NULL;
sec_fix = sec_only_builds[key];

bmatch = eregmatch(pattern:'^VMware ESXi?.*build-([0-9]+)$', string:rel);
if (empty_or_null(bmatch))
  audit(AUDIT_UNKNOWN_BUILD, product, ver);

build = int(bmatch[1]);

if (!fix)
  audit(AUDIT_INST_VER_NOT_VULN, product, ver, build);

if (build < fix && build != sec_fix)
{
  # if there is a security fix
  if (sec_fix)
    fix = fix + " / " + sec_fix;

  # properly spaced label
  if ("ESXi" >< esx) ver_label = ' version    : ';
  else ver_label = ' version     : ';
  report = '\n  ' + esx + ver_label + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fix +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, product, ver, build);
