#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(63685);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/01/24 22:22:01 $");

  script_cve_id("CVE-2012-5978");
  script_bugtraq_id(56942);
  script_osvdb_id(88461);
  script_xref(name:"VMSA", value:"2012-0017");

  script_name(english:"VMware View Server Directory Traversal Vulnerability (VMSA-2012-0017)");
  script_summary(english:"Checks VMware View Server version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a desktop solution that affected by a directory
traversal vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of VMware View Server installed on the remote host is
potentially affected by a directory traversal vulnerability in the
Connection Server and View Security Server.  This may allow a remote
attacker to read arbitrary files from the system."
  );

  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0017.html");
  # http://ddilabs.blogspot.com/2012/12/vmware-view-connection-server-directory.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c7ce514");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware View 4.6.2 / 5.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:view");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("vmware_view_server_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/ViewServer/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

appname = "VMware View Server";
path    = get_kb_item_or_exit("VMware/ViewServer/Path");
version = get_kb_item_or_exit("VMware/ViewServer/Version");

vulnerable = NULL;
fix = NULL;

if (version =~ '^4\\.')
{
  fix = '4.6.2';
  vulnerable = ver_compare(ver:version, fix:fix, strict:FALSE);
} 
else if (version =~ '^5\\.')
{
  fix = '5.1.2';
  vulnerable = ver_compare(ver:version, fix:fix, strict:FALSE);
}

if (vulnerable < 0)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning();
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
