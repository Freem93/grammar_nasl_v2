#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89737);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
    "CVE-2008-3916",
    "CVE-2008-4316",
    "CVE-2008-4552",
    "CVE-2009-0115",
    "CVE-2009-0590",
    "CVE-2009-1189",
    "CVE-2009-1377",
    "CVE-2009-1378",
    "CVE-2009-1379",
    "CVE-2009-1386",
    "CVE-2009-1387",
    "CVE-2009-2695",
    "CVE-2009-2849",
    "CVE-2009-2904",
    "CVE-2009-2905",
    "CVE-2009-2908",
    "CVE-2009-3228",
    "CVE-2009-3286",
    "CVE-2009-3547",
    "CVE-2009-3560",
    "CVE-2009-3563",
    "CVE-2009-3612",
    "CVE-2009-3613",
    "CVE-2009-3620",
    "CVE-2009-3621",
    "CVE-2009-3720",
    "CVE-2009-3726",
    "CVE-2009-4022"
  );
  script_bugtraq_id(
    30815,
    31602,
    31823,
    34100,
    34256,
    35001,
    35138,
    35174,
    36304,
    36515,
    36552,
    36639,
    36706,
    36723,
    36824,
    36827,
    36901,
    36936,
    37118,
    37203,
    37255
  );
  script_osvdb_id(
    48045,
    49182,
    52864,
    53486,
    54612,
    54613,
    54614,
    55072,
    55073,
    56165,
    56386,
    57209,
    57757, 
    57821,
    58323,
    58330,
    58495,
    58880,
    59068,
    59070,
    59210,
    59211,
    59222,
    59654,
    59737,
    59877,
    60493,
    60797,
    60847
  );
  script_xref(name:"VMSA", value:"2010-0004");

  script_name(english:"VMware ESX Third-Party Libraries Multiple Vulnerabilities (VMSA-2010-0004) (remote check)");
  script_summary(english:"Checks the ESX / ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX host is missing a security-related patch. It is,
therefore, affected by multiple vulnerabilities, including remote code
execution vulnerabilities, in several third-party components and
libraries :

  - bind
  - expat
  - glib2
  - Kernel
  - newt
  - nfs-utils
  - NTP
  - OpenSSH
  - OpenSSL");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2010-0004");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2010/000104.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 3.5 / 4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 20, 119, 189, 200, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/03");
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
          "4.0", "236512",
          "3.5", "283373"
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
