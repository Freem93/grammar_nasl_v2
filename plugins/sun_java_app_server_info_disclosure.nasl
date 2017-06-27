#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68958);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/17 17:13:09 $");

  script_cve_id("CVE-2009-0278");
  script_bugtraq_id(33397);
  script_osvdb_id(51604);
  script_xref(name:"IAVT", value:"2009-T-0009");

  script_name(english:"Sun Java System Application Server Information Disclosure");
  script_summary(english:"Checks version of Sun Java System Application Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application server installed that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Sun Java System Application Server installed on the
remote host is potentially affected by an information disclosure
vulnerability.  A remote, unauthenticated attacker could exploit this
flaw to read the Web Application configuration files in the WEB-INF or
META-INF directory via a specially crafted request.");
  # http://web.archive.org/web/20090210021510/http://sunsolve.sun.com/search/document.do?assetkey=1-66-245446-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0b5fee2");
  script_set_attribute(attribute:"solution", value:"Apply the relevant vendor patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:java_system_application_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("global_settings.inc");
include("bsal.inc");
include("byte_func.inc");
include("zip.inc");

# Connect to the appropriate share
name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
paths = make_array();

key = "SOFTWARE\Sun Microsystems\Application Server";
subkeys = get_registry_subkeys(handle:hklm, key:key);
foreach subkey (subkeys)
{
  if (subkey =~ '^[0-9\\.]+')
  {
    path = get_registry_value(handle:hklm, item:key + '\\' + subkey + "\INSTALLPATH");
    if (!isnull(path)) paths[subkey] = path;
  }
}
RegCloseKey(handle:hklm);

if (max_index(keys(paths)) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, 'Sun Java System Application Server');
}
close_registry(close:FALSE);

installs = 0;
lastshare = '';
vers = make_array();
foreach key (keys(paths))
{
  path = paths[key];
  share = hotfix_path2share(path:path);
  jar = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\lib\appserv-admin.jar", string:path);

  if (share != lastshare)
  {
    NetUseDel(close:FALSE);
    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      continue;
    }
  }

  fh = CreateFile(
    file:jar,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    continue;
  }

  version = '';
  build = '';
  idx = 0;
  res = zip_parse(smb:fh, 'com/sun/appserv/server/util/Version.class');
  if ('sun-appserver-' >< res)
  {
    chunk = strstr(res, 'sun-appserver-') - 'sun-appserver-';
    chunk = substr(chunk, 2);
    chunk = chunk - strstr(chunk, 'java/util');
    chunk = chomp(substr(chunk, 2));
    for (i = 1; i <= ord(chunk[0]); i++)
      version += chunk[i];
    ver = split(version, sep:'.', keep:FALSE);

    idx += ord(chunk[0]) + 3;
    idx += ord(chunk[idx]) + 3;
    idx += ord(chunk[idx]) + 3;
    for (i = idx+1; i <= idx + ord(chunk[idx]); i++)
      build += chunk[i];
    vers[key] = make_array('version', version, 'build', build);
  }
  CloseFile(handle:fh);
}
NetUseDel();

info = '';
info2 = '';
vuln = 0;
foreach key (keys(vers))
{
  path = paths[key];
  install = vers[key];
  version = install['version'];
  build = install['build'];

  buildnum = ereg_replace(pattern:'^[a-z]([0-9]+).*', string:build, replace:"\1");
  if (version =~ '^8\\.1([^0-9\\.]|$)' && int(buildnum) < 47)
  {
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + ' ' + build +
      '\n  Fixed version     : 8.1_02 b47-p24\n';
    vuln++;
  }
  else if (version =~ '^8\\.2([^0-9\\.]|$)' && int(buildnum) < 39)
  {
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + ' ' + build +
      '\n  Fixed version     : 8.2 b39-p07\n';
    vuln++;
  }
  else info2 += ' and ' + version + ' ' + build;
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1)
      s = 's of Sun Java System Application Server were';
    else s = ' of Sun Java System Application Server was';

    report =
      '\n  The following vulnerable version' + s +
      '\n  found on the remote host : \n' +
      info + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}

if (info2)
{
  info2 -= ' and ';
  if (' and ' >< info2) be = 'are';
  else be = 'is';

  exit(0, 'The host is not affected since Sun Java System Application Server '+info2+' '+be+' installed.');
}
else exit(1, 'Unexpected error - \'info2\' is empty.');
