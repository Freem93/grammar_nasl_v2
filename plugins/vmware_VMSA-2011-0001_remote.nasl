#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89673);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/07 14:48:53 $");

  script_cve_id(
    "CVE-2010-0211",
    "CVE-2010-0212",
    "CVE-2010-2956",
    "CVE-2010-3847",
    "CVE-2010-3856"
  );
  script_bugtraq_id(
    41770,
    43019,
    44154,
    44347
  );
  script_osvdb_id(
    66469,
    66470,
    67842,
    68721,
    68920
  );
  script_xref(name:"VMSA", value:"2011-0001");

  script_name(english:"VMware ESX Third-Party Libraries Multiple Vulnerabilities (VMSA-2011-0001) (remote check)");
  script_summary(english:"Checks the ESX version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX host is missing a security-related patch. It is,
therefore, affected by multiple vulnerabilities, including arbitrary
code execution vulnerabilities, in several third-party components and
libraries :

  - glibc
  - glibc-common
  - nscd
  - openldap
  - sudo");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2011-0001");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2011/000150.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 4.0 / 4.1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/04");
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

if ("ESX" >!< rel || "ESXi" >< rel)
  audit(AUDIT_OS_NOT, "VMware ESX");

extract = eregmatch(pattern:"^ESX (\d\.\d).*$", string:ver);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_APP_VER, "VMware ESX/ESXi");
else
  ver = extract[1];

if (ver !~ "^4\.[01]")
  audit(AUDIT_INST_VER_NOT_VULN, "VMware ESX", ver);

fixes = make_array(
          "4.0", "332073",
          "4.1", "348481"
        );

fix = fixes[ver];

extract = eregmatch(pattern:'^VMware ESX.* build-([0-9]+)$', string:rel);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_BUILD, "VMware ESX", ver);

build = int(extract[1]);

if (build < fix)
{
  report = '\n  Version         : ESX ' + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fix +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);

}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware ESX", ver, build);
