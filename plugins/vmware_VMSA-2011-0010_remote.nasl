#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89679);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/17 13:39:45 $");

  script_cve_id(
    "CVE-2010-0296",
    "CVE-2011-0536",
    "CVE-2011-0997",
    "CVE-2011-1071",
    "CVE-2011-1095",
    "CVE-2011-1658",
    "CVE-2011-1659"
  );
  script_bugtraq_id(
    44154,
    46563,
    47176,
    47370
  );
  script_osvdb_id(
    66751,
    65078,
    68721,
    71493,
    72796,
    73407,
    75261
  );
  script_xref(name:"VMSA", value:"2011-0010");
  script_xref(name:"CERT", value:"537223");
  script_xref(name:"CERT", value:"107886");

  script_name(english:"VMware ESX Third-Party Libraries Multiple Vulnerabilities (VMSA-2011-0010) (remote check)");
  script_summary(english:"Checks the ESX version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX host is missing a security-related patch. It is,
therefore, affected by multiple vulnerabilities, including arbitrary
code execution vulnerabilities, in several third-party components and
libraries :

  - DHCP
  - glibc");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2011-0010");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000163.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 3.5 / 4.0 / 4.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/28");
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
esx = 'ESX';

if ("ESX" >!< rel || "ESXi" >< rel)
  audit(AUDIT_OS_NOT, "VMware ESX");

extract = eregmatch(pattern:"^ESX (\d\.\d).*$", string:ver);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_APP_VER, "VMware ESX");
else
  ver = extract[1];

fixes = make_array(
          "3.5", "604481",
          "4.0", "480973",
          "4.1", "433742"
        );

fix = FALSE;
fix = fixes[ver];

# get the build before checking the fix for the most complete audit trail
extract = eregmatch(pattern:'^VMware ESX.* build-([0-9]+)$', string:rel);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_BUILD, "VMware " + esx, ver);
else
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
