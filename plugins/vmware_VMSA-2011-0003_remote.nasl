#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89674);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
    "CVE-2008-0085",
    "CVE-2008-0086",
    "CVE-2008-0106",
    "CVE-2008-0107",
    "CVE-2008-3825",
    "CVE-2008-5416",
    "CVE-2009-1384",
    "CVE-2009-2693",
    "CVE-2009-2901",
    "CVE-2009-2902",
    "CVE-2009-3548",
    "CVE-2009-3555",
    "CVE-2009-4308",
    "CVE-2010-0003",
    "CVE-2010-0007",
    "CVE-2010-0008",
    "CVE-2010-0082",
    "CVE-2010-0084",
    "CVE-2010-0085",
    "CVE-2010-0087",
    "CVE-2010-0088",
    "CVE-2010-0089",
    "CVE-2010-0090",
    "CVE-2010-0091",
    "CVE-2010-0092",
    "CVE-2010-0093",
    "CVE-2010-0094",
    "CVE-2010-0095",
    "CVE-2010-0291",
    "CVE-2010-0307",
    "CVE-2010-0410",
    "CVE-2010-0415",
    "CVE-2010-0433",
    "CVE-2010-0437",
    "CVE-2010-0622",
    "CVE-2010-0730",
    "CVE-2010-0734",
    "CVE-2010-0740",
    "CVE-2010-0837",
    "CVE-2010-0838",
    "CVE-2010-0839",
    "CVE-2010-0840",
    "CVE-2010-0841",
    "CVE-2010-0842",
    "CVE-2010-0843",
    "CVE-2010-0844",
    "CVE-2010-0845",
    "CVE-2010-0846",
    "CVE-2010-0847",
    "CVE-2010-0848",
    "CVE-2010-0849",
    "CVE-2010-0850",
    "CVE-2010-0886",
    "CVE-2010-1084",
    "CVE-2010-1085",
    "CVE-2010-1086",
    "CVE-2010-1087",
    "CVE-2010-1088",
    "CVE-2010-1157",
    "CVE-2010-1173",
    "CVE-2010-1187",
    "CVE-2010-1321",
    "CVE-2010-1436",
    "CVE-2010-1437",
    "CVE-2010-1641",
    "CVE-2010-2066",
    "CVE-2010-2070",
    "CVE-2010-2226",
    "CVE-2010-2227",
    "CVE-2010-2240",
    "CVE-2010-2248",
    "CVE-2010-2521",
    "CVE-2010-2524",
    "CVE-2010-2928",
    "CVE-2010-2939",
    "CVE-2010-3081",
    "CVE-2010-3541",
    "CVE-2010-3548",
    "CVE-2010-3549",
    "CVE-2010-3550",
    "CVE-2010-3551",
    "CVE-2010-3553",
    "CVE-2010-3554",
    "CVE-2010-3556",
    "CVE-2010-3557",
    "CVE-2010-3559",
    "CVE-2010-3561",
    "CVE-2010-3562",
    "CVE-2010-3565",
    "CVE-2010-3566",
    "CVE-2010-3567",
    "CVE-2010-3568",
    "CVE-2010-3569",
    "CVE-2010-3571",
    "CVE-2010-3572",
    "CVE-2010-3573",
    "CVE-2010-3574",
    "CVE-2010-3864"
  );
  script_bugtraq_id(
    30082,
    30083,
    30118,
    30119,
    31534,
    32710,
    35112,
    36935,
    36954,
    37724,
    37762,
    37906,
    37942,
    37944,
    37945,
    38027,
    38058,
    38144,
    38162,
    38165,
    38185,
    38348,
    38479,
    38533,
    38857,
    38898,
    39013,
    39044,
    39062,
    39067,
    39068,
    39069,
    39070,
    39071,
    39072,
    39073,
    39075,
    39077,
    39078,
    39081,
    39082,
    39083,
    39084,
    39085,
    39086,
    39088,
    39089,
    39090,
    39091,
    39093,
    39094,
    39095,
    39096,
    39120,
    39492,
    39569,
    39635,
    39715,
    39719,
    39794,
    39979,
    40235,
    40356,
    40776,
    40920,
    41466,
    41544,
    41904,
    42242,
    42249,
    42306,
    43239,
    43965,
    43971,
    43979,
    43985,
    43988,
    43992,
    43994,
    44009,
    44011,
    44012,
    44013,
    44014,
    44016,
    44017,
    44026,
    44027,
    44028,
    44030,
    44032,
    44035,
    44040,
    44884
  );
  script_osvdb_id(
    46770,
    46771,
    46772,
    46773,
    48784,
    50589,
    54791,
    60176,
    61035,
    61670,
    61784,
    61984,
    62045,
    62052,
    62053,
    62054,
    62079,
    62168,
    62217,
    62379,
    62380,
    62507,
    62719,
    63146,
    63257,
    63299,
    63452,
    63481,
    63482,
    63483,
    63484,
    63485,
    63486,
    63487,
    63488,
    63489,
    63490,
    63491,
    63492,
    63493,
    63494,
    63495,
    63496,
    63497,
    63498,
    63499,
    63500,
    63501,
    63502,
    63503,
    63504,
    63505,
    63506,
    63630,
    63631,
    63632,
    63633,
    63634,
    63635,
    63636,
    63798,
    64023,
    64549,
    64557,
    64630,
    64744,
    64865,
    65066,
    65541,
    65631,
    66319,
    66582,
    66946,
    67237,
    67243,
    67244,
    67892,
    68213,
    69033,
    69034,
    69035,
    69036,
    69038,
    69039,
    69040,
    69041,
    69042,
    69044,
    69045,
    69047,
    69049,
    69050,
    69052,
    69053,
    69055,
    69056,
    69057,
    69058,
    69059,
    69265,
    70083,
    70859
  );
  script_xref(name:"VMSA", value:"2011-0003");

  script_name(english:"VMware ESX / ESXi Third-Party Libraries Multiple Vulnerabilities (VMSA-2011-0003) (remote check)");
  script_summary(english:"Checks the ESX / ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.
It is, therefore, affected by multiple vulnerabilities, including
remote code execution vulnerabilities, in several third-party
components and libraries :

  - Apache Tomcat 
  - Apache Tomcat Manager
  - cURL 
  - Java Runtime Environment (JRE)
  - Kernel 
  - Microsoft SQL Express
  - OpenSSL
  - pam_krb5");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2011-0003");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2011/000140.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 4.0 / 4.1 or ESXi version 4.0 / 4.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Plugin Command Line Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 22, 119, 189, 200, 255, 264, 287, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
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
esx = '';

if ("ESX" >!< rel)
  audit(AUDIT_OS_NOT, "VMware ESX/ESXi");

extract = eregmatch(pattern:"^(ESXi?) (\d\.\d).*$", string:ver);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_APP_VER, "VMware ESX/ESXi");
else
{
  esx = extract[1];
  ver = extract[2];
}

# fixed build numbers are the same for ESX and ESXi
fixes = make_array(
          "4.0", "360236",
          "4.1", "348481"
        );

fix = FALSE;
fix = fixes[ver];

# get the build before checking the fix for the most complete audit trail
extract = eregmatch(pattern:'^VMware ESXi?.* build-([0-9]+)$', string:rel);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_BUILD, "VMware " + esx, ver);

build = int(extract[1]);

# if there is no fix in the array, fix is FALSE
if (!fix)
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + esx, ver, build);

if (build < fix)
{

  report = '\n  Version         : ' + esx + " " + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fix +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + esx, ver, build);
