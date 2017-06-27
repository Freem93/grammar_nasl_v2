#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89670);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/07 14:48:53 $");

  script_cve_id(
    "CVE-2012-2372",
    "CVE-2012-3552",
    "CVE-2013-0791",
    "CVE-2013-1620",
    "CVE-2013-2147",
    "CVE-2013-2164",
    "CVE-2013-2206",
    "CVE-2013-2224",
    "CVE-2013-2232",
    "CVE-2013-2234",
    "CVE-2013-2237"
  );
  script_bugtraq_id(
    54062, 
    55359, 
    57777, 
    58826, 
    60280, 
    60375, 
    60715, 
    60858, 
    60874, 
    60893, 
    60953
  );
  script_osvdb_id(
    83056, 
    85723, 
    89848, 
    91885, 
    94027, 
    94033, 
    94456, 
    94698, 
    94706, 
    94793, 
    94853
  );
  script_xref(name:"VMSA", value:"2013-0015");

  script_name(english:"VMware ESX Third-Party Libraries Multiple Vulnerabilities (VMSA-2013-0015) (remote check)");
  script_summary(english:"Checks the version and build numbers of the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.
It is, therefore, affected by multiple vulnerabilities, including
remote code execution vulnerabilities, in several third-party
libraries :

  - Kernel
  - Netscape Portable Runtime (NSPR)
  - Network Security Services (NSS)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2013-0015");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 4.0 / 4.1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");
  script_require_ports("Host/VMware/vsphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit("Host/VMware/version");
rel   = get_kb_item_or_exit("Host/VMware/release");
port  = get_kb_item_or_exit("Host/VMware/vsphere");
esx   = '';
build = 0;
fix   = FALSE;

if ("ESX" >!< rel || "ESXi" >< rel)
  audit(AUDIT_OS_NOT, "VMware ESX");

extract = eregmatch(pattern:"^ESX (\d\.\d).*$", string:ver);
if (empty_or_null(extract))
  audit(AUDIT_UNKNOWN_APP_VER, "VMware ESX/ESXi");

ver = extract[1];

extract = eregmatch(pattern:'^VMware ESX.* build-([0-9]+)$', string:rel);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_BUILD, "VMware ESX", ver);

build = int(extract[1]);

fixes = make_array(
    "4.1", 1363503,
    "4.0", -1
);

fix = fixes[ver];

if (!fix)
  audit(AUDIT_INST_VER_NOT_VULN, "VMware ESX", ver, build);

if (build < fix || fix == -1)
{
  if (fix == -1)
    fixl = '\n  Note            : No patch was ever released.';
  else
    fixl = '\n  Fixed build     : ' + fix;
  report = '\n  Version         : ' + esx + " " + ver +
           '\n  Installed build : ' + build +
           fixl +'\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware ESX", ver, build);
