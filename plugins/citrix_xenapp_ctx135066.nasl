#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(63339);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/06/10 20:49:25 $");

  script_cve_id("CVE-2012-5161");
  script_bugtraq_id(56907);
  script_osvdb_id(88368);
  script_xref(name:"IAVB", value:"2012-B-0127");

  script_name(english:"Citrix XenApp XML Service Interface Crafted Packet Parsing Remote Code Execution (CTX135066)");
  script_summary(english:"Checks version of wpnbr.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenApp installed on the remote Windows host is
potentially affected by an unspecified vulnerability in the XML service
interface. An unauthenticated, remote attacker can exploit this to
execute arbitrary code on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX135066");
  script_set_attribute(attribute:"solution", value:"Apply the relevant vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xenapp");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

port    = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

appname = 'Citrix XenApp';

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Make sure the software is installed and 
# get the path
xapath = NULL;
prodver = NULL;

# Make sure Xenapp is installed
item = "SOFTWARE\Citrix\XenApp\Commands\Install";
if (!isnull(get_registry_value(handle:handle, item:item)))
{
  item = "SOFTWARE\Citrix\Install\Location";
  xapath = get_registry_value(handle:handle, item:item);
}
RegCloseKey(handle:handle);

if (isnull(xapath))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else close_registry(close:FALSE);

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:xapath);
sys = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1system32\wpnbr.dll", string:xapath);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:sys,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  close_registry();
  audit(AUDIT_UNINST, appname);
}

ver = GetFileVersion(handle:fh);
prodver = GetProductVersion(handle:fh);
CloseFile(handle:fh);
close_registry();

filePath = (share - '$')+':'+sys;
if (isnull(ver)) audit(AUDIT_VER_FAIL, filePath); 
if (isnull(prodver)) exit(1, 'Couldn\'t determine the product version from ' + filePath); 

version = join(ver, sep:'.');
major = int(ver[0]);
minor = int(ver[1]);
rev = int(ver[2]);
build = int(ver[3]);
fix = NULL;

if (prodver == '6.0' && build == 6682  && rev < 6500 && version =~ '^6\\.0') fix = '6.0.36.6682';
else if (prodver == '6.0' && build == 6682 && version =~ '^6\\.0\\.65') fix = '6.0.6535.6682';

if (fix)
{
  if (ver_compare(ver:version, fix:fix) == -1)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  File              : ' + filePath +  
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_INST_PATH_NOT_VULN, appname, version, xapath);
