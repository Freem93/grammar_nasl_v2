#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70727);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/06/23 19:16:51 $");

  script_cve_id("CVE-2013-3285");
  script_bugtraq_id(63402);
  script_osvdb_id(99067);

  script_name(english:"EMC NetWorker 8.x < 8.0.2.3 Management Console Information Disclosure");
  script_summary(english:"Checks version of EMC NetWorker");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC NetWorker is 8.x earlier than 8.0.2.3. As such, it
is potentially affected by an information disclosure vulnerability.
When the NetWorker Management Console is configured to use Active
Directory/LDAP for authentication, an authenticated user may be able
to see the AD/LDAP administrator password transmitted in cleartext.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Oct/att-152/ESA-2013-072.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to EMC NetWorker 8.0.2.3 / 8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:networker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("emc_networker_installed.nasl");
  script_require_keys("installed_sw/EMC NetWorker");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

appname  = "EMC NetWorker";
install  = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
version  = install['version'];
path     = install['path'];

fix = '';
if (version =~ '^8\\.0\\.' && ver_compare(ver:version, fix:'8.0.2.3', strict:FALSE) < 0) fix = '8.0.2.3';

if (fix)
{
  ad = FALSE;
  # See if the NMC is installed and configured to use AD
  name   = kb_smb_name();
  port   = kb_smb_transport();
  if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  path = NULL;
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  key = "SOFTWARE\Legato\GST";
  subkeys = get_registry_subkeys(handle:hklm, key:key);
  foreach subkey (subkeys)
  {
    if (subkey =~ '[0-9\\.]Build\\.[0-9]+')
    {
      path = get_registry_value(handle:hklm, item:key + '\\' + subkey + "\InstallPath");
      break;
    }
  }
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);

  if (isnull(path))
  {
    close_registry();
    exit(1, 'Failed to determine the configuration file path for EMC NetWorker Management Console.');
  }

  share = hotfix_path2share(path:path);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    close_registry();
    audit(AUDIT_SHARE_FAIL, share);
  }

  config = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\GST\cst\Config.xml", string:path);
  fh = CreateFile(
    file:config,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (isnull(fh))
  {
    NetUseDel();
    exit(1, 'Failed to open a handle on ' + path + "\GST\cst\Config.xml");
  }

  fsize = GetFileSize(handle:fh);
  if (fsize)
  {
    off = 0;
    while (off < fsize)
    {
      data = ReadFile(handle:fh, length:10240, offset:off);
      if (strlen(data) == 0) break;

      if ('<class-id class="LDAP"/>' >< data)
      {
        ad = TRUE;
        break;
      }
      off += 10240;
    }
  }
  CloseFile(handle:fh);
  NetUseDel();

  if (ad)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  else
  {
    exit(0, 'The host is not affected because the EMC NetWorker Management Console does not use Active Directory.');
  }
}
audit(AUDIT_INST_PATH_NOT_VULN, 'EMC NetWorker', version, path);
