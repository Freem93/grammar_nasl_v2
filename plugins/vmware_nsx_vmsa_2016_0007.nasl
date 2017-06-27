#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95260);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/11/23 20:42:25 $");

  script_cve_id("CVE-2016-2079");
  script_osvdb_id(139639);
  script_xref(name:"VMSA", value:"2016-0007");

  script_name(english:"VMware NSX Edge Information Disclosure (VMSA-2016-0007)");
  script_summary(english:"Checks the version of VMware NSX Edge.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware NSX Edge installed on the remote host is 6.1.x
prior to 6.1.7 or 6.2.x prior to 6.2.3. It is, therefore, affected by
a flaw in the SSL-VPN feature due to improper validation of input. An
unauthenticated, remote attacker can exploit this to disclose
potentially sensitive information. Note that this issue only applies
when SSL-VPN is enabled.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0007");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware NSX Edge version 6.1.7 / 6.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:nsx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_nsx_installed.nbin");
  script_require_keys("Host/VMware NSX/Version", "Host/VMware NSX/Build", "Host/VMware NSX/Product");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

product_name = "VMware NSX Edge";

product = get_kb_item_or_exit("Host/VMware NSX/Product");
if (product != "Edge") audit(AUDIT_HOST_NOT, product_name);

version = get_kb_item_or_exit("Host/VMware NSX/Version");
build   = get_kb_item_or_exit("Host/VMware NSX/Build");
sslvpn  = get_kb_item("Host/VMware NSX/SSLVPN-Plus");

fix = '';
if (version =~ '^6\\.2\\.' && int(build) < '3979471') fix = '6.2.3 Build 3979471';
else if (version =~ '^6\\.1\\.' && int(build) < '3949567') fix = '6.1.7 Build 3949567';
else audit(AUDIT_INST_VER_NOT_VULN, product_name, version, build);

caveat = '';
if (sslvpn == FALSE) audit(AUDIT_HOST_NOT,"affected");
if (sslvpn == "unknown")
{
  if (report_paranoia < 2) audit(AUDIT_PARANOID);
  caveat = '\nNote that Nessus was unable to determine if the SSL VPN-Plus service was enabled.\n';
}

report =
  '\n  Installed product : ' + product_name +
  '\n  Installed version : ' + version + ' Build ' + build +
  '\n  Fixed version     : ' + fix +
  '\n' + caveat;
security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
