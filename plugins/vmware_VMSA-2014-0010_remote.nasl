#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87680);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id(
    "CVE-2014-6271",
    "CVE-2014-6277",
    "CVE-2014-6278",
    "CVE-2014-7169",
    "CVE-2014-7186",
    "CVE-2014-7187"
  );
  script_bugtraq_id(
    70103,
    70137,
    70152,
    70154,
    70165,
    70166
  );
  script_osvdb_id(
    112004,
    112096,
    112097,
    112158,
    112169

  );
  script_xref(name:"VMSA", value:"2014-0010");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");

  script_name(english:"VMware ESX Multiple Bash Vulnerabilities (VMSA-2014-0010) (Shellshock)");
  script_summary(english:"Checks the version and build numbers of the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX host is affected by multiple vulnerabilities 
in the Bash shell :

  - A command injection vulnerability exists in GNU Bash
    known as Shellshock. The vulnerability is due to the
    processing of trailing strings after function
    definitions in the values of environment variables. This
    allows a remote attacker to execute arbitrary code via
    environment variable manipulation depending on the
    configuration of the system. (CVE-2014-6271,
    CVE-2014-7169, CVE-2014-6277, CVE-2014-6278)

  - A out-of-bounds read error exists in the redirection
    implementation in file parse.y when evaluating
    untrusted input during stacked redirects handling. A
    remote attacker can exploit this to cause a denial of
    service or possibly have other unspecified impact.
    (CVE-2014-7186)

  - An off-by-one overflow condition exists in the
    read_token_word() function in file parse.y when handling
    deeply nested flow control structures. A remote attacker
    can exploit this, by using deeply nested for-loops, to
    cause a denial of service or possibly execute arbitrary
    code. (CVE-2014-7187)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2014-0010");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2014/000278.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dacf7829");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/2014/09/cve-2014-6271/");
  # http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e40f2f5a");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 4.0 / 4.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

pci = FALSE;
pci = get_kb_item("Settings/PCI_DSS");

if ("ESX " >!< rel)
  audit(AUDIT_OS_NOT, "VMware ESX");

esx = "ESXi";

extract = eregmatch(pattern:"^ESX (\d\.\d).*$", string:ver);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_APP_VER, "VMware ESX");
else
  ver = extract[1];

# fixed build numbers are the same for ESX and ESXi
fixes = make_array(
          "4.0", "2167889",
          "4.1", "See vendor"
        );

fix = FALSE;
fix = fixes[ver];

# get the build before checking the fix for the most complete audit trail
extract = eregmatch(pattern:'^VMware ESX.* build-([0-9]+)$', string:rel);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_BUILD, "VMware ESX", ver);

build = int(extract[1]);

# if there is no fix in the array, fix is FALSE
if(!fix)
  audit(AUDIT_INST_VER_NOT_VULN, "VMware ESX", ver, build);

if (!pci && fix == "See vendor")
  audit(AUDIT_PCI);

vuln = FALSE;

# This is for PCI reporting
if (pci && fix == "See vendor")
  vuln = TRUE;
else if (build < fix )
  vuln = TRUE;

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version         : ESX ' + ver +
             '\n  Installed build : ' + build +
             '\n  Fixed build     : ' + fix +
             '\n';
    security_hole(port:port, extra:report);
  }
  else
    security_hole(port:port);

  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware ESX", ver, build);
