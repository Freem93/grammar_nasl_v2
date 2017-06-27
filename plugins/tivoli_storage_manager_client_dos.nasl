#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64569);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/03/14 19:33:40 $");

  script_cve_id("CVE-2013-0471");
  script_bugtraq_id(57737);
  script_osvdb_id(89835);

  script_name(english:"IBM Tivoli Storage Manager Client Denial of Service");
  script_summary(english:"Checks version of Tivoli Storage Manager Client");

  script_set_attribute(attribute:"synopsis", value:
"A client application installed on the remote Windows host is affected
by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Tivoli Storage Manager Client installed on the remote
Windows host is potentially affected by a denial of service
vulnerability in the TSM client traditional scheduler which allows a
remote attacker to disable the traditional scheduler when it is in
Prompted mode.");

  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_tsm_client_scheduler_denial_of_service_vulnerability_cve_2013_04714?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fde62a71");
  script_set_attribute(attribute:"solution", value:"Upgrade to Tivoli Storage Manager Client 6.2.5.0, 6.3.1.0, 6.4.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("tivoli_storage_manager_client_installed.nasl");
  script_require_keys("SMB/Tivoli Storage Manager Client/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Tivoli Storage Manager Client/Version");
path = get_kb_item_or_exit("SMB/Tivoli Storage Manager Client/Path");

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

fix = '';
if (version =~ '^6\\.2\\.' && ver_compare(ver:version, fix:'6.2.5.0') < 0) fix = '6.2.5.0';
else if (version =~ '^6\\.3\\.' && ver_compare(ver:version, fix:'6.3.1.0') < 0) fix = '6.3.1.0';
else if (version =~ '^6\\.4\\.' && ver_compare(ver:version, fix:'6.4.0.1') < 0) fix = '6.4.0.1';
else if (version =~ '^([0-4]\\.|5\\.[0-5]\\.|6\\.1\\.[0-5]\\.)') fix = '6.3.1.0 / 6.4.0.1';

workaround = FALSE;
if (fix)
{
  # If a vulnerable version was found, check for the workaround
  # before issuing a report
  registry_init();
  share = hotfix_path2share(path:path);

  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  opt = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\dsm.opt", string:path);
  fh = CreateFile(
    file:opt,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (isnull(fh))
  {
    NetUseDel();
    exit(1, "Failed to open the file " + path + "\dsm.opt.");
  }

  fsize = GetFileSize(handle:fh);
  off = 0;
  if (fsize)
  { 
    while (off <= fsize)
    {
      data = ReadFile(handle:fh, length:10240, offset:off);
      if (strlen(data) == 0) break;
  
      if (
        ereg(string:data, pattern:'SCHEDMODE\\s+POLLING', multiline:TRUE) ||
        ereg(string:data, pattern:'MANAGEDSERVICES\\s+SCHEDULE(\\s+WEBCLIENT)?', multiline:TRUE)
      )
      {
        workaround = TRUE;
        break;
      }
      off += 10240;
    }
  }
  CloseFile(handle:fh);
  NetUseDel();

  if (!workaround)
  {
    port = get_kb_item("SMB/transport");
    if (!port) port = 445;

    if (report_verbosity > 0)
    {
      report = 
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version + 
        '\n  Fixed version     : ' + fix + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  else exit(0, 'The host is not affected because the workaround is in place.');
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Tivoli Storage Manager Client', version, path);
