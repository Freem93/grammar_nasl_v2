#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89106);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id(
    "CVE-2010-0405",
    "CVE-2011-3190",
    "CVE-2011-3375",
    "CVE-2011-3389",
    "CVE-2011-3516",
    "CVE-2011-3521",
    "CVE-2011-3544",
    "CVE-2011-3545",
    "CVE-2011-3546",
    "CVE-2011-3547",
    "CVE-2011-3548",
    "CVE-2011-3549",
    "CVE-2011-3550",
    "CVE-2011-3551",
    "CVE-2011-3552",
    "CVE-2011-3553",
    "CVE-2011-3554",
    "CVE-2011-3555",
    "CVE-2011-3556",
    "CVE-2011-3557",
    "CVE-2011-3558",
    "CVE-2011-3560",
    "CVE-2011-3561",
    "CVE-2012-0022",
    "CVE-2012-1508",
    "CVE-2012-1510",
    "CVE-2012-1512"
  );
  script_bugtraq_id(
    43331,
    49353,
    49778,
    50118,
    50211,
    50215,
    50216,
    50218,
    50220,
    50223,
    50224,
    50226,
    50229,
    50231,
    50234,
    50236,
    50237,
    50239,
    50242,
    50243,
    50246,
    50248,
    50250,
    51442,
    51447,
    52524,
    52525
  );
  script_osvdb_id(
    68167,
    74818,
    74829,
    76495,
    76496,
    76497,
    76498,
    76499,
    76500,
    76501,
    76502,
    76503,
    76504,
    76505,
    76506,
    76507,
    76508,
    76509,
    76510,
    76511,
    76512,
    76513,
    78331,
    78573,
    80115,
    80117,
    80119
  );
  script_xref(name:"VMSA", value:"2012-0005");
  script_xref(name:"IAVB", value:"2010-B-0083");
  script_xref(name:"CERT", value:"864643");
  script_xref(name:"EDB-ID", value:"18171");

  script_name(english:"VMware ESX / ESXi Multiple Vulnerabilities (VMSA-2012-0005) (BEAST) (remote check)");
  script_summary(english:"Checks the remote ESX/ESXi host's version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi / ESX host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.
It is, therefore, affected by multiple vulnerabilities, including
remote code execution vulnerabilities, in the following components :

  - Apache Tomcat
  - bzip2 library
  - JRE
  - WDDM display driver
  - XPDM display driver");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2012-0005.html");
  # http://www.oracle.com/technetwork/topics/security/javacpuoct2011-443431.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3fed43a3");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Rhino Script Engine Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  "ESX 4.0",  480973,
  "ESXi 4.0", 480973,
  "ESX 4.1",  800380,
  "ESXi 4.1", 502767,
  "ESXi 5.0", 623860
);

# security-only fix builds
sec_only_builds = make_array(
  "ESX 4.1",  811144,
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
