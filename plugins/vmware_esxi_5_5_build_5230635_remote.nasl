#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(99129);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/03 15:09:40 $");

  script_cve_id(
    "CVE-2017-4904",
    "CVE-2017-4905"
  );
  script_bugtraq_id(
    97164,
    97165
  );
  script_osvdb_id(
    154021,
    154022
  );
  script_xref(name:"VMSA", value:"2017-0006");
  script_xref(name:"IAVB", value:"2017-B-0036");

  script_name(english:"ESXi 5.5 < Build 5230635 Multiple Vulnerabilities (VMSA-2017-0006) (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.5 host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the remote VMware ESXi 5.5 host is prior to build
5230635. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in memory initialization that
    allows an attacker on the guest to execute arbitrary
    code on the host. (CVE-2017-4904)

  - An unspecified flaw exists in memory initialization that
    allows the disclosure of sensitive information.
    (CVE-2017-4905)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2017-0006.html");
  script_set_attribute(attribute:"solution", value:
"Apply patch ESXi550-201703401-SG according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");

if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");
if ("VMware ESXi 5.5" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.5");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", "5.5");

build = int(match[1]);
fixed_build = 5230635;

if (build < fixed_build)
{
  report = '\n  ESXi version    : ' + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver - "ESXi " + " build " + build);
