#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69101);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/09 15:53:03 $");

  script_cve_id("CVE-2012-0393");
  script_bugtraq_id(51257);
  script_osvdb_id(78109);
  script_xref(name:"VMSA", value:"2012-0013");

  script_name(english:"VMware vCenter Operations Manager Arbitrary File Upload (VMSA-2012-0013)");
  script_summary(english:"Checks version of vCenter Operations Manager");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization appliance installed that is
affected by an arbitrary file upload vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of vCenter Operations Manager installed on the remote host
is earlier than 5.0.3.  It is, therefore, potentially affected by an
arbitrary file upload vulnerability in the Apache Struts component.  By
exploiting this flaw, a remote, unauthenticated attacker could overwrite
arbitrary files on the remote host subject to the privileges of the user
running the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0013.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to vCenter Operations Manager 5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vCenter Operations Manager/Version");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware vCenter Operations Manager/Version");

if (
  version =~ '^1\\.0\\.' ||
  (version =~ '^5\\.0\\.' && ver_compare(ver:version, fix:'5.0.3', strict:FALSE) < 0)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.0.3\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware vCenter Operations Manager', version);
