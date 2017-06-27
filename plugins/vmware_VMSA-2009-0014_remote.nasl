#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89116);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
    "CVE-2007-6063",
    "CVE-2008-0598",
    "CVE-2008-2086",
    "CVE-2008-2136",
    "CVE-2008-2812",
    "CVE-2008-3275",
    "CVE-2008-3525",
    "CVE-2008-4210",
    "CVE-2008-5339",
    "CVE-2008-5340",
    "CVE-2008-5341",
    "CVE-2008-5342",
    "CVE-2008-5343",
    "CVE-2008-5344",
    "CVE-2008-5345",
    "CVE-2008-5346",
    "CVE-2008-5347",
    "CVE-2008-5348",
    "CVE-2008-5349",
    "CVE-2008-5350",
    "CVE-2008-5351",
    "CVE-2008-5352",
    "CVE-2008-5353",
    "CVE-2008-5354",
    "CVE-2008-5355",
    "CVE-2008-5356",
    "CVE-2008-5357",
    "CVE-2008-5358",
    "CVE-2008-5359",
    "CVE-2008-5360",
    "CVE-2009-0692",
    "CVE-2009-1093",
    "CVE-2009-1094",
    "CVE-2009-1095",
    "CVE-2009-1096",
    "CVE-2009-1097",
    "CVE-2009-1098",
    "CVE-2009-1099",
    "CVE-2009-1100",
    "CVE-2009-1101",
    "CVE-2009-1102",
    "CVE-2009-1103",
    "CVE-2009-1104",
    "CVE-2009-1105",
    "CVE-2009-1106",
    "CVE-2009-1107",
    "CVE-2009-1893"
  );
  script_bugtraq_id(
    26605,
    29235,
    29942,
    30076,
    30647,
    31368,
    32608,
    32620,
    32892,
    34240,
    35668,
    35670
  );
  script_osvdb_id(
    39240,
    45421,
    46918,
    46920,
    46921,
    46922,
    46923,
    46924,
    46925,
    46926,
    47788,
    48432,
    48781,
    49081,
    50495,
    50496,
    50497,
    50498,
    50499,
    50500,
    50501,
    50502,
    50503,
    50504,
    50505,
    50506,
    50507,
    50508,
    50509,
    50510,
    50511,
    50512,
    50513,
    50514,
    50515,
    50516,
    50517,
    53164,
    53165,
    53166,
    53167,
    53168,
    53169,
    53170,
    53171,
    53172,
    53173,
    53174,
    53175,
    53176,
    53177,
    53178,
    55819,
    56464
  );
  script_xref(name:"VMSA", value:"2009-0014");

  script_name(english:"VMware ESX / ESXi Multiple Vulnerabilities (VMSA-2009-0014) (remote check)");
  script_summary(english:"Checks the ESX / ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.
It is, therefore, affected by multiple vulnerabilities, including
remote code execution vulnerabilities, in the following components :

  - ISC DHCP dhclient
  - Integrated Services Digital Network (ISDN) subsystem
  - Java Runtime Environment (JRE)
  - Java SE Development Kit (JDK)
  - Java SE Web Start
  - Linux kernel
  - Linux kernel 32-bit and 64-bit emulation
  - Linux kernel Simple Internet Transition INET6
  - Linux kernel tty
  - Linux kernel virtual file system (VFS)
  - Red Hat dhcpd init script for DHCP
  - SBNI WAN driver");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2009-0014");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX / ESXi version 3.5 / 4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Calendar Deserialization Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 20, 59, 94, 119, 189, 200, 264, 287, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
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

app_name = "VMware ESX";

version = get_kb_item_or_exit("Host/VMware/version");
release = get_kb_item_or_exit("Host/VMware/release");
port    = get_kb_item_or_exit("Host/VMware/vsphere");

fixes = make_array();
fixes["ESX 3.5"]  = 199239;
fixes["ESX 4.0"]  = 219382;
fixes["ESXi 4.0"] = 208167;

matches = eregmatch(pattern:'^VMware (ESXi?).*build-([0-9]+)$', string:release);
if (empty_or_null(matches))
  exit(1, 'Failed to extract the ESX / ESXi build number.');

type  = matches[1];
build = int(matches[2]);

fixed_build = fixes[version];

if (!isnull(fixed_build) && build < fixed_build)
{
  padding = crap(data:" ", length:8 - strlen(type)); # Spacing alignment

  report = '\n  ' + type + ' version' + padding + ': ' + version +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';

  security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + version + " build " + build);
