#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89105);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
    "CVE-2009-3560",
    "CVE-2009-3720",
    "CVE-2010-0547",
    "CVE-2010-0787",
    "CVE-2010-1634",
    "CVE-2010-2059",
    "CVE-2010-2089",
    "CVE-2010-3493",
    "CVE-2010-4649",
    "CVE-2011-0695",
    "CVE-2011-0711",
    "CVE-2011-0726",
    "CVE-2011-1015",
    "CVE-2011-1044",
    "CVE-2011-1078",
    "CVE-2011-1079",
    "CVE-2011-1080",
    "CVE-2011-1093",
    "CVE-2011-1163",
    "CVE-2011-1166",
    "CVE-2011-1170",
    "CVE-2011-1171",
    "CVE-2011-1172",
    "CVE-2011-1182",
    "CVE-2011-1494",
    "CVE-2011-1495",
    "CVE-2011-1521",
    "CVE-2011-1573",
    "CVE-2011-1576",
    "CVE-2011-1577",
    "CVE-2011-1593",
    "CVE-2011-1678",
    "CVE-2011-1745",
    "CVE-2011-1746",
    "CVE-2011-1763",
    "CVE-2011-1776",
    "CVE-2011-1780",
    "CVE-2011-1936",
    "CVE-2011-2022",
    "CVE-2011-2192",
    "CVE-2011-2213",
    "CVE-2011-2482",
    "CVE-2011-2491",
    "CVE-2011-2492",
    "CVE-2011-2495",
    "CVE-2011-2517",
    "CVE-2011-2519",
    "CVE-2011-2522",
    "CVE-2011-2525",
    "CVE-2011-2689",
    "CVE-2011-2694",
    "CVE-2011-2901",
    "CVE-2011-3378"
  );
  script_bugtraq_id(
    36097,
    37203,
    37992,
    38326,
    40370,
    40863,
    44533,
    46073,
    46417,
    46488,
    46541,
    46616,
    46793,
    46839,
    46878,
    46919,
    47003,
    47024,
    47308,
    47343,
    47497,
    47534,
    47535,
    47791,
    47796,
    47843,
    48048,
    48058,
    48333,
    48441,
    48538,
    48641,
    48677,
    48899,
    48901,
    49141,
    49370,
    49373,
    49375,
    49408,
    49939
  );
  script_osvdb_id(
    59737,
    60797,
    62155,
    62186,
    64957,
    65143,
    65144,
    65151,
    68739,
    70950,
    71330,
    71331,
    71361,
    71480,
    71649,
    71653,
    71656,
    71992,
    72993,
    73042,
    73043,
    73045,
    73046,
    73047,
    73048,
    73049,
    73295,
    73296,
    73297,
    73328,
    73459,
    73460,
    73686,
    73802,
    73872,
    73882,
    74071,
    74072,
    74635,
    74642,
    74649,
    74650,
    74653,
    74654,
    74655,
    74656,
    74657,
    74658,
    74660,
    74676,
    74868,
    74872,
    74873,
    75240,
    75241,
    75930,
    75931
  );
  script_xref(name:"VMSA", value:"2012-0001");

  script_name(english:"VMware ESX / ESXi Service Console and Third-Party Libraries Multiple Vulnerabilities (VMSA-2012-0001) (remote check)");
  script_summary(english:"Checks the remote ESX/ESXi host's version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi / ESX host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.
It is, therefore, affected by multiple vulnerabilities, including
remote code execution vulnerabilities, in several third-party
libraries :

  - COS kernel
  - cURL
  - python
  - rpm");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2012-0001.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 59, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/30");
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
