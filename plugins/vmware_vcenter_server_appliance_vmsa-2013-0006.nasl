#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67141);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/12/14 06:22:31 $");

  script_cve_id("CVE-2013-3079", "CVE-2013-3080");
  script_bugtraq_id(59507, 59509);
  script_osvdb_id(92811, 92813);
  script_xref(name:"VMSA", value:"2013-0006");

  script_name(english:"VMware vCenter Server Appliance Multiple Vulnerabilities (VMSA-2013-0006)");
  script_summary(english:"Checks version of VMware vCenter Server Appliance");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization appliance installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server Appliance installed on the remote
host is 5.1 earlier than Update 1, and is, therefore, potentially
affected by multiple vulnerabilities :

  - An authenticated code execution vulnerability exists in
    the Virtual Appliance Management Interface.
    (CVE-2013-3079)

  - The Virtual Appliance Management Interface contains a
    vulnerability that allows an authenticated, remote
    attacker to upload files to an arbitrary location.
    (CVE-2013-3080)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0006.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware vCenter Server Appliance 5.1 Update 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vCenter Server Appliance/Version", "Host/VMware vCenter Server Appliance/Build");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware vCenter Server Appliance/Version");
build = get_kb_item_or_exit("Host/VMware vCenter Server Appliance/Build");

if (version =~ '^5\\.1\\.0$' && int(build) < 1065184)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version + ' Build ' + build +
      '\n  Fixed version     : 5.1.0 Build 1065184\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware vCenter Server Appliance', version + ' Build ' + build);
