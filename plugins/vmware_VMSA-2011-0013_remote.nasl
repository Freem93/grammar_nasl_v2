#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89681);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id(
    "CVE-2008-7270",
    "CVE-2010-1321",
    "CVE-2010-2054",
    "CVE-2010-3170",
    "CVE-2010-3173",
    "CVE-2010-3541",
    "CVE-2010-3548",
    "CVE-2010-3549",
    "CVE-2010-3550",
    "CVE-2010-3551",
    "CVE-2010-3552",
    "CVE-2010-3553",
    "CVE-2010-3554",
    "CVE-2010-3555",
    "CVE-2010-3556",
    "CVE-2010-3557",
    "CVE-2010-3558",
    "CVE-2010-3559",
    "CVE-2010-3560",
    "CVE-2010-3561",
    "CVE-2010-3562",
    "CVE-2010-3563",
    "CVE-2010-3565",
    "CVE-2010-3566",
    "CVE-2010-3567",
    "CVE-2010-3568",
    "CVE-2010-3569",
    "CVE-2010-3570",
    "CVE-2010-3571",
    "CVE-2010-3572",
    "CVE-2010-3573",
    "CVE-2010-3574",
    "CVE-2010-4180",
    "CVE-2010-4422",
    "CVE-2010-4447",
    "CVE-2010-4448",
    "CVE-2010-4450",
    "CVE-2010-4451",
    "CVE-2010-4452",
    "CVE-2010-4454",
    "CVE-2010-4462",
    "CVE-2010-4463",
    "CVE-2010-4465",
    "CVE-2010-4466",
    "CVE-2010-4467",
    "CVE-2010-4468",
    "CVE-2010-4469",
    "CVE-2010-4470",
    "CVE-2010-4471",
    "CVE-2010-4472",
    "CVE-2010-4473",
    "CVE-2010-4474",
    "CVE-2010-4475",
    "CVE-2010-4476",
    "CVE-2011-0002",
    "CVE-2011-0802",
    "CVE-2011-0814",
    "CVE-2011-0815",
    "CVE-2011-0862",
    "CVE-2011-0864",
    "CVE-2011-0865",
    "CVE-2011-0867",
    "CVE-2011-0871",
    "CVE-2011-0873"
  );
  script_bugtraq_id(
    40235,
    40475,
    42817,
    43965,
    43971,
    43979,
    43985,
    43988,
    43992,
    43994,
    43999,
    44009,
    44011,
    44012,
    44013,
    44014,
    44016,
    44017,
    44020,
    44021,
    44023,
    44024,
    44026,
    44027,
    44028,
    44030,
    44032,
    44035,
    44038,
    44040,
    45164,
    45254,
    45791,
    46091,
    46386,
    46387,
    46388,
    46391,
    46393,
    46394,
    46395,
    46397,
    46398,
    46399,
    46400,
    46402,
    46403,
    46404,
    46405,
    46406,
    46407,
    46409,
    46410,
    46411,
    48137,
    48139,
    48142,
    48143,
    48144,
    48145,
    48147,
    48148,
    48149
  );
  script_osvdb_id(
    64744,
    65157,
    68079,
    68844,
    68873,
    69033,
    69034,
    69035,
    69036,
    69037,
    69038,
    69039,
    69040,
    69041,
    69042,
    69043,
    69044,
    69045,
    69046,
    69047,
    69048,
    69049,
    69050,
    69051,
    69052,
    69053,
    69055,
    69056,
    69057,
    69058,
    69059,
    69565,
    69655,
    70083,
    70421,
    70965,
    71193,
    71605,
    71606,
    71607,
    71608,
    71609,
    71610,
    71611,
    71612,
    71613,
    71614,
    71615,
    71616,
    71617,
    71618,
    71619,
    71620,
    71621,
    71622,
    71623,
    73069,
    73070,
    73071,
    73074,
    73075,
    73076,
    73077,
    73083,
    73085,
    73176
  );
  script_xref(name:"VMSA", value:"2011-0013");

  script_name(english:"VMware ESX / ESXi Third-Party Libraries Multiple Vulnerabilities (VMSA-2011-0013) (remote check)");
  script_summary(english:"Checks the ESX / ESXi version and build number.");

  script_set_attribute(attribute:"synopsis",  value:
"The remote VMware ESX / ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.
It is, therefore, affected by multiple vulnerabilities, including
remote code execution vulnerabilities, in several third-party
components and libraries :

  - Java Runtime Environment (JRE)
  - libuser
  - Netscape Portable Runtime (NSPR) 
  - Network Security Services (NSS)
  - OpenSSL");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2011-0013");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000169.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 4.0 / 4.1 or ESXi version 4.0 / 4.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Applet2ClassLoader Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/27");
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
          "4.0", "660575",
          "4.1", "502767"
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
