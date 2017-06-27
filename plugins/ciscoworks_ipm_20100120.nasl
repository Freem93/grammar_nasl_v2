#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69447);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/09/04 15:20:59 $");

  script_cve_id("CVE-2010-0138");
  script_bugtraq_id(37879);
  script_osvdb_id(61908);
  script_xref(name:"IAVA", value:"2010-A-0017");

  script_name(english:"CiscoWorks Internetwork Performance Monitor CORBA GIOP Overflow");
  script_summary(english:"Checks version of CiscoWorks IPM");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of CiscoWorks Internetwork Performance Monitor installed 
on the remote Windows host is less than or equal to 2.6.  Such 
versions are potentially affected by a buffer overflow vulnerability
when processing Common Object Request Broker Architecture GIOP 
requests.  By exploiting this flaw, a remote, unauthenticated attacker
could execute arbitrary code subject to the privileges of the user
running the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/csa/cisco-sa-20100120-ipm.html");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for instructions on migrating to non-vulnerable
software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:ciscoworks_internetwork_performance_monitor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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

app = 'CiscoWorks Internetwork Performance Monitor';
name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Cisco\Resource Manager\CurrentVersion\RootDir\NMSROOT";
path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
close_registry(close:FALSE);

if ('PROGRA~1' >< path) path = str_replace(string:path, find:'PROGRA~1', replace:'Program Files');

share = hotfix_path2share(path:path);
inf = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\setup\ipm.info", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:inf,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  NetUseDel();
  audit(AUDIT_UNINST, app);
}

version = NULL;
fsize = GetFileSize(handle:fh);
if (isnull(fsize)) fsize = 10240;
off = 0;
while (off <= fsize)
{
  data = ReadFile(handle:fh, length:10240, offset:off);
  if (strlen(data) == 0) break;

  # Make sure this is for Internetwork Performance Monitor and grab the version
  if ('Internetwork Performance Monitor' >< data && 'VERSION=' >< data)
  {
    version = strstr(data, 'VERSION=') - 'VERSION=';
    version = version - strstr(data, 'PATCHVER');
    version = chomp(version);
    break;
  }
  off += 10240;
}

CloseFile(handle:fh);
NetUseDel();

if (isnull(version) || version !~ '^[0-9\\.]+$') audit(AUDIT_VER_FAIL, (share - '$') + ':' + inf);

if (ver_compare(ver:version, fix:'2.6', strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
