#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70878);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id("CVE-2013-1661");
  script_bugtraq_id(62077);
  script_osvdb_id(96761);
  script_xref(name:"VMSA", value:"2013-0011");
  script_xref(name:"IAVB", value:"2013-B-0095");
  script_xref(name:"IAVB", value:"2013-B-0096");
  script_xref(name:"IAVB", value:"2013-B-0098");

  script_name(english:"ESXi 5.0 < Build 1197855 NFC Traffic Denial of Service (remote check)");
  script_summary(english:"Checks ESXi version and build number");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.0 host is affected by denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi 5.0 host is affected by an unspecified error
related to handling Network File Copy (NFC) traffic that could allow
denial of service attacks.");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2053139");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0011.html");
  script_set_attribute(attribute:"solution", value:"Apply patch ESXi500-201308101-SG.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

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
if ("VMware ESXi 5.0" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.0");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) exit(1, 'Failed to extract the ESXi build number.');

build = int(match[1]);
fixed_build = 1197855;

if (build < fixed_build)
{
  if (report_verbosity > 0)
  {
    report = '\n  ESXi version    : ' + ver +
             '\n  Installed build : ' + build +
             '\n  Fixed build     : ' + fixed_build +
             '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else exit(0, "The host has "+ver+" build "+build+" and thus is not affected.");
