#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89739);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/09 15:14:04 $");

  script_cve_id(
    "CVE-2009-3732",
    "CVE-2010-1141",
    "CVE-2010-1142"
  );
  script_bugtraq_id(
    39392,
    39394,
    39396
  );
  script_osvdb_id(
    63605,
    63858,
    63859
  );
  script_xref(name:"VMSA", value:"2010-0007");
  script_xref(name:"EDB-ID", value:"12188");

  script_name(english:"VMware ESX Multiple Vulnerabilities (VMSA-2010-0007) (remote check)");
  script_summary(english:"Checks the ESX / ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX host is missing a security-related patch. It is,
therefore, affected by multiple vulnerabilities :

  - A format string flaw exists in the VMware Remote Console
    that allows a remote attacker to execute arbitrary code.
    (CVE-2009-3732)

  - A flaw exists in VMware Tools due to improper access to
    libraries. A remote attacker can exploit this to execute
    arbitrary code by convincing a Windows guest OS user
    into clicking on a file that is stored on a network
    share. (CVE-2010-1141)

  - A flaw exists in VMware Tools due to improper loading of
    VMware programs. An attacker with access to a Windows
    guest OS can escalate privileges by placing a Trojan
    horse program at an unspecified location on the guest OS
    disk. (CVE-2010-1142)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2010-0007");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2010/000091.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 3.5 / 4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(134);

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/09");
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
          "3.5", "226117"
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
