#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77963);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/11/23 13:44:59 $ ");

  script_cve_id("CVE-2014-3796");
  script_bugtraq_id(69756);
  script_osvdb_id(111382);
  script_xref(name:"VMSA", value:"2014-0009");

  script_name(english:"VMware NSX Edge Unspecified Information Disclosure (VMSA-2014-0009)");
  script_summary(english:"Checks the version of VMware NSX Edge.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an unspecified information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware NSX Edge installed on the remote host is 6.0.x
prior to 6.0.6. It is, therefore, affected by an unspecified
information disclosure vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0009");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware NSX Edge version 6.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/29");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:nsx");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_nsx_installed.nbin");
  script_require_keys("Host/VMware NSX/Version", "Host/VMware NSX/Build", "Host/VMware NSX/Product");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

product_name = "VMware NSX Edge";

product = get_kb_item_or_exit("Host/VMware NSX/Product");
if ( product != "Edge" ) audit(AUDIT_HOST_NOT, product_name);

version = get_kb_item_or_exit("Host/VMware NSX/Version");
build   = get_kb_item_or_exit("Host/VMware NSX/Build");

if (version =~ '^6\\.0(\\.|$)' && int(build) < 2103699)
{
  report =
    '\n  Installed product : ' + product_name +
    '\n  Installed version : ' + version + ' Build ' + build +
    '\n  Fixed version     : 6.0.6 Build 2103699\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, product_name, version, build);
