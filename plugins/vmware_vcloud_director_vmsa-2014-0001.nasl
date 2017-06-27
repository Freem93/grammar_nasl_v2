#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72119);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/06/24 21:32:06 $");

  script_cve_id("CVE-2014-1211");
  script_bugtraq_id(64993);
  script_osvdb_id(102198);
  script_xref(name:"VMSA", value:"2014-0001");

  script_name(english:"VMware vCloud Director 5.1.x < 5.1.3 Logout XSRF (VMSA-2014-0001)");
  script_summary(english:"Checks the version of VMware vCloud Director.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected
by a cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCloud Director installed on the remote host is
5.1.x prior to 5.1.3. It is, therefore, affected by a cross-site
request forgery (XSRF) vulnerability due to an error in HTTP session
management. A remote attacker can exploit this, by convincing a user
to follow specially crafted link, to cause the user to be logged out.
Note that the victimized user would be able to immediately log back
into the system.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2014-0001");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCloud Director version 5.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcloud_director");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcloud_director_installed.nbin");
  script_require_keys("Host/VMware vCloud Director/Version", "Host/VMware vCloud Director/Build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware vCloud Director/Version");
build = get_kb_item_or_exit("Host/VMware vCloud Director/Build");

fixed_ver = "5.1.3";
fixed_build = "1489357";

if ( version =~ '^5\\.1\\.' && (ver_compare(ver:version, fix:fixed_ver, strict:FALSE) < 0) )
{
  report =
    '\n  Installed version : ' + version + ' Build ' + build +
    '\n  Fixed version     : ' + fixed_ver + ' Build ' + fixed_build +
    '\n';

  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING, xsrf:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware vCloud Director', version + ' Build ' + build);
