#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99474);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/04/19 16:18:45 $");

  script_cve_id("CVE-2017-5641");
  script_bugtraq_id(97383);
  script_osvdb_id(155134);
  script_xref(name:"VMSA", value:"2017-0007");
  script_xref(name:"CERT", value:"307983");

  script_name(english:"VMware vCenter Server Appliance BlazeDS AMF3 RCE (VMSA-2017-0007)");
  script_summary(english:"Checks the version of VMware vCenter Server Appliance.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server Appliance installed on the remote
host is 6.0 prior to Update 3b or 6.5 prior to Update c. It is,
therefore, affected by a flaw in FlexBlazeDS when processing AMF3
messages due to allowing the instantiation of arbitrary classes when
deserializing objects. An unauthenticated, remote attacker can exploit
this, by sending a specially crafted Java object, to execute arbitrary
code.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0007.html");
  # http://pubs.vmware.com/Release_Notes/en/vsphere/60/vsphere-vcenter-server-60u3b-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e032520");
  # http://pubs.vmware.com/Release_Notes/en/vsphere/65/vsphere-vcenter-server-650c-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a1fa223");
  script_set_attribute(attribute:"see_also", value:"http://codewhitesec.blogspot.de/2017/04/amf.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server Appliance 6.0 Update 3b / 6.5 Update
c or later. Alternatively, apply the vendor-supplied workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vCenter Server Appliance/Version", "Host/VMware vCenter Server Appliance/Build");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = 'VMware vCenter Server Appliance';
version = get_kb_item_or_exit("Host/"+appname+"/Version");
build   = get_kb_item_or_exit("Host/"+appname+"/Build");
port    = 0;
fixversion_str = NULL;

if (
  version !~ "^6\.0($|[^0-9])" &&
  version !~ "^6\.5($|[^0-9])"
)
  audit(AUDIT_NOT_INST, appname + " 6.0.x / 6.5.x");

if (version =~ "^6\.0($|[^0-9])")
{
  fixed_main_ver = "6.0.0";
  fixed_build    = 5326079;

  if (int(build) < fixed_build)
    fixversion_str = fixed_main_ver + ' build-'+fixed_build;
}
else if (version =~ "^6\.5($|[^0-9])")
{
  fixed_main_ver = "6.5.0";
  fixed_build    = 5318112;

  if (int(build) < fixed_build)
    fixversion_str = fixed_main_ver + ' build-'+fixed_build;
}

if (isnull(fixversion_str))
  audit(AUDIT_INST_VER_NOT_VULN, appname, version, build);

report = report_items_str(
  report_items:make_array(
    "Installed version", version + ' build-' + build,
    "Fixed version", fixed_main_ver + ' build-' + fixed_build
  ),
  ordered_fields:make_list("Installed version", "Fixed version")
);
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
