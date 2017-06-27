#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89736);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
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
    "CVE-2009-2625",
    "CVE-2009-2670",
    "CVE-2009-2671",
    "CVE-2009-2672",
    "CVE-2009-2673",
    "CVE-2009-2675",
    "CVE-2009-2676",
    "CVE-2009-2716",
    "CVE-2009-2718",
    "CVE-2009-2719",
    "CVE-2009-2720",
    "CVE-2009-2721",
    "CVE-2009-2722",
    "CVE-2009-2723",
    "CVE-2009-2724",
    "CVE-2009-3728",
    "CVE-2009-3729",
    "CVE-2009-3864",
    "CVE-2009-3865",
    "CVE-2009-3866",
    "CVE-2009-3867",
    "CVE-2009-3868",
    "CVE-2009-3869",
    "CVE-2009-3871",
    "CVE-2009-3872",
    "CVE-2009-3873",
    "CVE-2009-3874",
    "CVE-2009-3875",
    "CVE-2009-3876",
    "CVE-2009-3877",
    "CVE-2009-3879",
    "CVE-2009-3880",
    "CVE-2009-3881",
    "CVE-2009-3882",
    "CVE-2009-3883",
    "CVE-2009-3884",
    "CVE-2009-3885",
    "CVE-2009-3886"
  );
  script_bugtraq_id(
    34240,
    35922,
    35939,
    35943,
    35944,
    35946,
    35958,
    36881
  );
  script_osvdb_id(
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
    57431,
    59705,
    59706,
    59707,
    59708,
    59709,
    59710,
    59711,
    59712,
    59713,
    59714,
    59716,
    59717,
    59718,
    59915,
    59916,
    59917,
    59918,
    59919,
    59920,
    59921,
    59922,
    59923,
    59924
  );
  script_xref(name:"VMSA", value:"2010-0002");

  script_name(english:"VMware ESX Java Runtime Environment (JRE) Multiple Vulnerabilities (VMSA-2010-0002) (remote check)");
  script_summary(english:"Checks the ESX / ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX host is missing a security-related patch. It is,
therefore, affected by multiple vulnerabilities, including remote code
execution vulnerabilities, in the bundled version of the Java Runtime
Environment (JRE).");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2010-0002");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2010/000097.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 3.5 / 4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 20, 22, 94, 119, 189, 200, 264, 310, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"VMware ESX Local Security Checks");

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
          "3.5", "227413",
          "4.0", "256968"
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
