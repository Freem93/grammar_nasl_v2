#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89117);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
    "CVE-2007-2052",
    "CVE-2007-4965",
    "CVE-2007-5333",
    "CVE-2007-5342",
    "CVE-2007-5461",
    "CVE-2007-5966",
    "CVE-2007-6286",
    "CVE-2008-0002",
    "CVE-2008-1232",
    "CVE-2008-1721",
    "CVE-2008-1887",
    "CVE-2008-1947",
    "CVE-2008-2315",
    "CVE-2008-2370",
    "CVE-2008-3142",
    "CVE-2008-3143",
    "CVE-2008-3144",
    "CVE-2008-3528",
    "CVE-2008-4307",
    "CVE-2008-4864",
    "CVE-2008-5031",
    "CVE-2008-5515",
    "CVE-2008-5700",
    "CVE-2009-0028",
    "CVE-2009-0033",
    "CVE-2009-0159",
    "CVE-2009-0269",
    "CVE-2009-0322",
    "CVE-2009-0580",
    "CVE-2009-0675",
    "CVE-2009-0676",
    "CVE-2009-0696",
    "CVE-2009-0745",
    "CVE-2009-0746",
    "CVE-2009-0747",
    "CVE-2009-0748",
    "CVE-2009-0778",
    "CVE-2009-0781",
    "CVE-2009-0783",
    "CVE-2009-0787",
    "CVE-2009-0834",
    "CVE-2009-1072",
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
    "CVE-2009-1192",
    "CVE-2009-1252",
    "CVE-2009-1336",
    "CVE-2009-1337",
    "CVE-2009-1385",
    "CVE-2009-1388",
    "CVE-2009-1389",
    "CVE-2009-1439",
    "CVE-2009-1630",
    "CVE-2009-1633",
    "CVE-2009-1895",
    "CVE-2009-2406",
    "CVE-2009-2407",
    "CVE-2009-2414",
    "CVE-2009-2416",
    "CVE-2009-2417",
    "CVE-2009-2625",
    "CVE-2009-2670",
    "CVE-2009-2671",
    "CVE-2009-2672",
    "CVE-2009-2673",
    "CVE-2009-2675",
    "CVE-2009-2676",
    "CVE-2009-2692",
    "CVE-2009-2698",
    "CVE-2009-2716",
    "CVE-2009-2718",
    "CVE-2009-2719",
    "CVE-2009-2720",
    "CVE-2009-2721",
    "CVE-2009-2722",
    "CVE-2009-2723",
    "CVE-2009-2724",
    "CVE-2009-2847",
    "CVE-2009-2848"
  );
  script_bugtraq_id(
    23887,
    25696,
    26070,
    26880,
    27006,
    27703,
    27706,
    28715,
    28749,
    29502,
    30491,
    30494,
    30496,
    31932,
    33187,
    33237,
    33412,
    33428,
    33618,
    33846,
    33906,
    33951,
    34084,
    34205,
    34216,
    34240,
    34390,
    34405,
    34453,
    34481,
    34612,
    34673,
    34934,
    35017,
    35185,
    35193,
    35196,
    35263,
    35281,
    35416,
    35559,
    35647,
    35848,
    35850,
    35851,
    35922,
    35929,
    35930,
    35939,
    35943,
    35944,
    35946,
    35958,
    36010,
    36032,
    36038,
    36108,
    49470
  );
  script_osvdb_id(
    35247,
    38187,
    39833,
    40142,
    40248,
    41434,
    41435,
    41436,
    44693,
    44730,
    45905,
    47462,
    47463,
    47478,
    47480,
    47481,
    49088,
    50092,
    50093,
    50094,
    50095,
    50096,
    50097,
    51000,
    51606,
    51653,
    52198,
    52201,
    52202,
    52203,
    52204,
    52364,
    52461,
    52631,
    52633,
    52860,
    52861,
    52899,
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
    53312,
    53362,
    53593,
    53629,
    53951,
    54379,
    54492,
    54498,
    54576,
    54892,
    55053,
    55054,
    55055,
    55056,
    55181,
    55679,
    55807,
    56444,
    56584,
    56690,
    56691,
    56783,
    56784,
    56785,
    56786,
    56788,
    56955,
    56956,
    56957,
    56958,
    56959,
    56961,
    56962,
    56964,
    56984,
    56985,
    56990,
    56992,
    56994,
    57208,
    57264,
    57431,
    57462
  );
  script_xref(name:"VMSA", value:"2009-0016");

  script_name(english:"VMware ESX / ESXi Multiple Vulnerabilities (VMSA-2009-0016) (remote check)");
  script_summary(english:"Checks the ESX / ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.
It is, therefore, affected by multiple vulnerabilities, including
remote code execution vulnerabilities, in the following components :

  - Apache Geronimo
  - Apache Tomcat
  - Apache Xerces2
  - cURL/libcURL
  - ISC BIND
  - Libxml2
  - Linux kernel
  - Linux kernel 64-bit
  - Linux kernel Common Internet File System
  - Linux kernel eCryptfs
  - NTP
  - Python
  - Java Runtime Environment (JRE)
  - Java SE Development Kit (JDK)
  - Java SE Abstract Window Toolkit (AWT)
  - Java SE Plugin
  - Java SE Provider
  - Java SE Swing
  - Java SE Web Start");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2009-0016");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX / ESXi version 3.5 / 4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel Sendpage Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 20, 22, 79, 94, 119, 189, 200, 264, 310, 362, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/20");
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

version = get_kb_item_or_exit("Host/VMware/version");
release = get_kb_item_or_exit("Host/VMware/release");
port    = get_kb_item_or_exit("Host/VMware/vsphere");

fixes = make_array();
fixes["ESX 3.5"]    = 227413;
fixes["ESXi 3.5"]   = 226117;
fixes["ESX 4.0"]    = 208167;
fixes["ESXi 4.0"]   = 208167;

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

  security_report_v4(extra:report, port:port, severity:SECURITY_HOLE, xss:TRUE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + version + " build " + build);
