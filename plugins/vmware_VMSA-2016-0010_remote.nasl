#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92949);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/05 20:47:50 $");

  script_cve_id("CVE-2016-5330", "CVE-2016-5331");
  script_bugtraq_id(92323, 92324);
  script_osvdb_id(142633, 142634);
  script_xref(name:"VMSA", value:"2016-0010");
  script_xref(name:"IAVB", value:"2016-B-0124");
  script_xref(name:"IAVB", value:"2016-B-0125");
  script_xref(name:"IAVB", value:"2016-B-0126");
  script_xref(name:"IAVB", value:"2016-B-0127");

  script_name(english:"ESXi 5.0 / 5.1 / 5.5 / 6.0 Multiple Vulnerabilities (VMSA-2016-0010) (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 5.0, 5.1, 5.5, or 6.0 and is
missing a security patch. It is, therefore, affected by multiple
vulnerabilities :

  - An arbitrary code execution vulnerability exists in the
    Shared Folders (HGFS) feature due to improper loading of
    Dynamic-link library (DLL) files from insecure paths,
    including the current working directory, which may not
    be under user control. A remote attacker can exploit
    this vulnerability, by placing a malicious DLL in the
    path or by convincing a user into opening a file on a
    network share, to inject and execute arbitrary code in
    the context of the current user. (CVE-2016-5330)

  - An HTTP header injection vulnerability exists due to
    improper sanitization of user-supplied input. A remote
    attacker can exploit this to inject arbitrary HTTP
    headers and conduct HTTP response splitting attacks.
    (CVE-2016-5331)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0010.html");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2142193");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2143976");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2141429");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2144359");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as referenced in the vendor advisory.

Note that VMware Tools on Windows-based guests that use the Shared
Folders (HGFS) feature must also be updated to completely mitigate
CVE-2016-5330.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'DLL Side Loading Vulnerability in VMware Host Guest Client Redirector');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

fixes = make_array(
  '5.0', '3982828',
  '5.1', '3872664',
  '5.5', '4179633',
  '6.0', '3620759'
);

security_only_patches = make_array(
  '5.0', '3982819',
  '5.1', '3872638',
  '5.5', '4179631',
  '6.0', '3568943'
);

rel = get_kb_item_or_exit("Host/VMware/release");
if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");

ver = get_kb_item_or_exit("Host/VMware/version");

match = pregmatch(pattern:"^ESXi? ([0-9]+\.[0-9]+).*$", string:ver);
ver = match[1];

if (ver != '5.0' && ver != '5.1' && ver != '5.5' && ver != '6.0')
  audit(AUDIT_OS_NOT, "ESXi 5.0 / 5.1 / 5.5 / 6.0");

fixed_build = fixes[ver];
security_only_patch = security_only_patches[ver];

if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

match = pregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", "5.0 / 5.1 / 5.5 / 6.0");

build = int(match[1]);

if (build < fixed_build && build != security_only_patch)
{
  if (!isnull(security_only_patch))
    fixed_build += ' / ' + security_only_patch + ' (security-only fix)';

  report = '\n  ESXi version    : ' + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';

  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver + " build " + build);
