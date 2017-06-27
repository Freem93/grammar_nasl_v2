#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91828);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/06/27 14:51:42 $");

  script_cve_id("CVE-2016-3427");
  script_osvdb_id(137303);
  script_xref(name:"VMSA", value:"2016-0005");

  script_name(english:"VMware vCloud Director 5.5.x < 5.5.6.1 / 5.6.x < 5.6.5.1 / 8.0.x < 8.0.1.1 JMX Deserialization RCE (VMSA-2016-0005)");
  script_summary(english:"Checks the version of VMware vCloud Director.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCloud Director installed on the remote host is
5.5.x prior to 5.5.6.1, 5.6.x prior to 5.6.5.1, or 8.0.x prior to
8.0.1.1. It is, therefore, affected by a flaw in the bundled Oracle
JRE JMX subcomponent due to deserializing any class when deserializing
authentication credentials. An unauthenticated, remote attacker can
exploit this to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0005.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCloud Director version 5.5.6.1 / 5.6.5.1 / 8.0.1.1
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcloud_director");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcloud_director_installed.nbin");
  script_require_keys("Host/VMware vCloud Director/Version", "Host/VMware vCloud Director/Build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware vCloud Director/Version");
build = get_kb_item_or_exit("Host/VMware vCloud Director/Build");

fixed_ver = '';
fixed_build = '';

if (version =~ "^5\.5\.")
{
  fixed_ver = '5.5.6.1';
  fixed_build = '3814538';
}
else if (version =~ "^5\.6\.")
{
  fixed_ver = '5.6.5.1';
  fixed_build = '3814650';
}
else if (version =~ "^8\.0\.")
{
  fixed_ver = '8.0.1.1';
  fixed_build = '3864078';
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware vCloud Director', version + ' Build ' + build);

if (
  (ver_compare(ver:version, fix:fixed_ver, strict:FALSE) < 0) &&
  (build < fixed_build)
)
{
  report = '\n  Installed version : ' + version + ' Build ' + build +
           '\n  Fixed version     : ' + fixed_ver + ' Build ' + fixed_build +
           '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware vCloud Director', version + ' Build ' + build);
