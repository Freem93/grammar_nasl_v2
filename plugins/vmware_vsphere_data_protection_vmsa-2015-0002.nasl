#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81315);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2014-4632");
  script_bugtraq_id(72367);
  script_osvdb_id(117768);
  script_xref(name:"VMSA", value:"2015-0002");
  script_xref(name:"IAVB", value:"2015-B-0016");

  script_name(english:"VMware vSphere Data Protection Certificate Validation (VMSA-2015-0002)");
  script_summary(english:"Checks the version of VMware vSphere Data Protection.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization appliance installed that is
affected by a certificate validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vSphere Data Protection installed on the remote
host is 5.1.x / 5.5.x prior to 5.5.9, or 5.8.x prior to 5.8.1. It is,
therefore, affected by a certificate validation vulnerability that
allows man-in-the-middle (MitM) attacks.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2015-0002.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2015/Jan/att-159/ESA-2015-006.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware vSphere Data Protection 5.5.9 / 5.8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vsphere_data_protection");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/vSphere Data Protection/Version");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "vSphere Data Protection";

version = get_kb_item_or_exit("Host/vSphere Data Protection/Version");
fix = NULL;

if (version =~ "^5(\.[58])?$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

if (version =~ "^5\.1($|[0-9])")
{
 fix = "5.2.0"; # not a real fix
 report_fix = "5.5.9 / 5.8.1";
}
else if (version =~ "^5\.5\.")
{
 fix = "5.5.9";
 report_fix = fix;
}
else if (version =~ "^5\.8\.")
{
 fix = "5.8.1";
 report_fix = fix;
}
else
  audit(AUDIT_NOT_INST, app_name +" 5.1.x / 5.5.x / 5.8.x");

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + report_fix +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
