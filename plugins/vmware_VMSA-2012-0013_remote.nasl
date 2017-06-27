#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89038);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/01 14:49:47 $");

  script_cve_id(
    "CVE-2009-5029",
    "CVE-2009-5064",
    "CVE-2010-0830",
    "CVE-2010-2761",
    "CVE-2010-4180",
    "CVE-2010-4252",
    "CVE-2010-4410",
    "CVE-2011-0014",
    "CVE-2011-1020",
    "CVE-2011-1089",
    "CVE-2011-1833",
    "CVE-2011-2484",
    "CVE-2011-2496",
    "CVE-2011-2699",
    "CVE-2011-3188",
    "CVE-2011-3209",
    "CVE-2011-3363",
    "CVE-2011-3597",
    "CVE-2011-4108",
    "CVE-2011-4109",
    "CVE-2011-4110",
    "CVE-2011-4128",
    "CVE-2011-4132",
    "CVE-2011-4324",
    "CVE-2011-4325",
    "CVE-2011-4576",
    "CVE-2011-4577",
    "CVE-2011-4609",
    "CVE-2011-4619",
    "CVE-2012-0050",
    "CVE-2012-0060",
    "CVE-2012-0061",
    "CVE-2012-0207",
    "CVE-2012-0393",
    "CVE-2012-0815",
    "CVE-2012-0841",
    "CVE-2012-0864",
    "CVE-2012-1569",
    "CVE-2012-1573",
    "CVE-2012-1583",
    "CVE-2012-2110"
  );
  script_bugtraq_id(
    40063,
    44199,
    45145,
    45163,
    45164,
    46264,
    46567,
    46740,
    47321,
    48383,
    48802,
    49108,
    49289,
    49626,
    49911,
    50311,
    50609,
    50663,
    50755,
    50798,
    50898,
    51194,
    51257,
    51281,
    51343,
    51366,
    51439,
    51467,
    51563,
    52009,
    52010,
    52011,
    52012,
    52013,
    52014,
    52015,
    52016,
    52017,
    52018,
    52019,
    52020,
    52107,
    52161,
    52201,
    52667,
    52668,
    52865,
    53136,
    53139,
    53158,
    53946,
    53947,
    53948,
    53949,
    53950,
    53951,
    53952,
    53953,
    53954,
    53956,
    53958,
    53959,
    53960
  );
  script_osvdb_id(
    65077,
    69565,
    69588,
    69589,
    69657,
    70847,
    71271,
    73451,
    74278,
    74659,
    74678,
    74879,
    74883,
    75580,
    75716,
    75990,
    76961,
    77092,
    77355,
    77450,
    77508,
    77599,
    77625,
    78108,
    78109,
    78114,
    78186,
    78187,
    78188,
    78189,
    78190,
    78225,
    78276,
    78277,
    78301,
    78316,
    78320,
    79225,
    79226,
    79227,
    79228,
    79229,
    79230,
    79231,
    79232,
    79233,
    79234,
    79235,
    79236,
    79437,
    80258,
    80259,
    80719,
    80724,
    81009,
    81010,
    81011,
    81223,
    81226,
    81227,
    81228,
    81229,
    81230,
    81231,
    81232,
    81233,
    81234,
    81235,
    81236,
    81237,
    81250,
    81441,
    82110,
    82874,
    82875,
    82876,
    82877,
    82878,
    82879,
    82880,
    82881,
    82882,
    82883,
    82884,
    82885,
    82886
  );
  script_xref(name:"VMSA", value:"2012-0013");

  script_name(english:"VMware ESX / ESXi Third-Party Libraries Multiple Vulnerabilities (VMSA-2012-0013) (remote check)");
  script_summary(english:"Checks the ESX / ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.
It is, therefore, affected by multiple vulnerabilities, including
remote code execution vulnerabilities, in several third-party
libraries :

  - Apache Struts
  - glibc
  - GnuTLS
  - JRE
  - kernel
  - libxml2
  - OpenSSL
  - Perl
  - popt and rpm");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0013.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 3.5 / 4.0 / 4.1 or ESXi version 3.5 / 4.0 /
4.1 / 5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache-Struts ExceptionDelegator < 2.3.1.1 RCE Linux");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");

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

version = get_kb_item_or_exit("Host/VMware/version");
release = get_kb_item_or_exit("Host/VMware/release");
port    = get_kb_item_or_exit("Host/VMware/vsphere");

# Version + build map
# https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1014508
fixes = make_array();
fixes["ESX 4.0"]  = 787047;
fixes["ESX 4.1"]  = 800380; # Full patch    -- 811144 is security-fix only
fixes["ESXi 4.1"] = 800380; # Full patch    -- 811144 is security-fix only
fixes["ESXi 5.0"] = 912577; # Security-only -- 914586 is full patch

# Extra fixes to report
extra_fixes = make_array();
extra_fixes["ESX 4.1"]  = 811144;
extra_fixes["ESXi 4.1"] = 811144;
extra_fixes["ESXi 5.0"] = 914586;

matches = eregmatch(pattern:'^VMware (ESXi?).*build-([0-9]+)$', string:release);
if (empty_or_null(matches))
  exit(1, 'Failed to extract the ESX / ESXi build number.');

type  = matches[1];
build = int(matches[2]);

fixed_build = fixes[version];

if (!isnull(fixed_build) && build < fixed_build)
{
  if (!empty_or_null(extra_fixes[version])) fixed_build += " / " + extra_fixes[version];
 
  padding = crap(data:" ", length:8 - strlen(type)); # Spacing alignment
 
  report = '\n  ' + type + ' version' + padding + ': ' + version +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';

  security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + version + " build " + build);
