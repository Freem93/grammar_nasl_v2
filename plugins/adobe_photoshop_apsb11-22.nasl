#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55815);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_cve_id("CVE-2011-2131");
  script_bugtraq_id(49106);
  script_osvdb_id(74422);
  script_xref(name:"EDB-ID", value:"17712");

  script_name(english:"Adobe Photoshop CS5 GIF File Memory Corruption (APSB11-22)");
  script_summary(english:"Checks Photoshop version");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop CS5 installed on the remote host
includes a filter plug-in, 'Standard MultiPlugin', that has a critical
memory corruption vulnerability.

If an attacker could trick a user on the affected system into opening
a malicious GIF file using the application, he could leverage the
vulnerability to execute arbitrary code remotely on the system subject
to the user's privileges. This could result in a system compromise.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-22.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop CS5 / CS5.1 if necessary, then apply the
Photoshop CS5 / CS5.1 Standard MultiPlugin Update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("SMB/Adobe_Photoshop/Installed");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

kb_base = "SMB/Adobe_Photoshop/";
get_kb_item_or_exit(kb_base+"Installed");

versions = get_kb_list(kb_base+'Version');
if (isnull(versions)) exit(1, "The '"+kb_base+"Version' KB list is missing.");


# Identify installs of CS5.1 and earlier.
paths = make_array();
info2 = '';

foreach version (versions)
{
  path = get_kb_item(kb_base+version+'/Path');
  if (isnull(path)) path = 'n/a';

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  verui = get_kb_item(kb_base+version+'/Version_UI');
  if (isnull(verui)) verui = version;

  if (
    ver[0] < 12 ||
    ver[0] == 12 && ver[1] <= 1
  )
  {
    paths[path] = version;
  }
  else info2 += " and " + verui;
}

if (max_index(keys(paths)) == 0)
{
  if (info2)
  {
    info2 -= " and ";
    if (" and " >< info2) be = "are";
    else be = "is";

    exit(0, "The host is not affected since Adobe Photoshop "+info2+" "+be+" installed.");
  }
  else exit(1, "Unexpected error - 'info2' is empty.");
}


# Establish a session.
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(1, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Failed to open a socket on port "+port+".");

#session_init(socket:soc, hostname:name);

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');


# Check each install we identified earlier.
info = '';
info2 = '';

foreach path (keys(paths))
{
  version = paths[path];

  # Determine the directory with Photoshop's plug-ins.
  plugin_path = "";
  match = eregmatch(pattern:"^([0-9]+\.[0-9]+)\.", string:version);
  if (!isnull(match))
  {
    highlevel_version = match[1];
    rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
    if (rc != 1)
    {
      NetUseDel();
      exit(1, "Can't connect to IPC$ share.");
    }

    hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
    if (isnull(hklm))
    {
      NetUseDel();
      exit(1, "Can't connect to remote registry.");
    }

    key = strcat("SOFTWARE\Adobe\Photoshop\", highlevel_version);
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      item = RegQueryValue(handle:key_h, item:"PluginPath");
      if (!isnull(item))
      {
        plugin_path = item[1];
        plugin_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:plugin_path);
      }
      RegCloseKey(handle:key_h);
    }
    if (!plugin_path)
    {
      key = strcat(key, "\PluginPath");
      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h))
      {
        item = RegQueryValue(handle:key_h, item:NULL);
        if (!isnull(item))
        {
          plugin_path = item[1];
          plugin_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:plugin_path);
        }
        RegCloseKey(handle:key_h);
      }
    }
    RegCloseKey(handle:hklm);
    NetUseDel(close:FALSE);
  }
  if (!plugin_path) plugin_path = path + "\Plug-ins";

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:plugin_path);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to "+share+" share.");
  }

  plugin =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Filters\Standard MultiPlugin.8BF", string:plugin_path);
  fh = CreateFile(
    file               : plugin,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    plugin_version = "";

    fsize = GetFileSize(handle:fh);
    chunk = 16384;

    if (fsize < 100000) ofs = 0;
    else ofs = int(fsize / 2);

    while (fsize > 0 && ofs <= fsize)
    {
      data = ReadFile(handle:fh, length:chunk, offset:ofs);
      if (strlen(data) == 0) break;
      data = str_replace(find:raw_string(0), replace:"", string:data);

      match = eregmatch(pattern:"\\([0-9]{8}\.[a-zA-Z]\.[0-9]+)\\", string:data);
      if (!isnull(match))
      {
        plugin_version = match[1];
        break;
      }
      ofs += chunk - 64;
    }

    CloseFile(handle:fh);

    if (!plugin_version)
    {
      NetUseDel();
      exit(1, "Couldn't get file version of '"+(share-'$')+":"+plugin+"'.");
    }

    yyyy = int(substr(plugin_version, 0, 3));
    mmdd = int(substr(plugin_version, 4, 7));
    r = int(substr(plugin_version, 11));
    if (
      yyyy < 2011 ||
      (yyyy == 2011 && mmdd < 0718)
    )
    {
      product_name = get_kb_item(kb_base+version+'/Product');
      if (isnull(product_name)) product_name = "Adobe Photoshop";

      info += '\n  Product           : ' + product_name +
              '\n  File              : ' + (share-'$')+":"+plugin +
              '\n  Installed version : ' + plugin_version +
              '\n  Fixed version     : 20110718.r.1299\n';
    }
    else info2 += " and " + plugin_version;
  }
  NetUseDel(close:FALSE);
}
NetUseDel();


# Report if an issue was found.
if (info)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Adobe Photoshop are";
    else s = " of Adobe Photoshop is";

    report =
      '\nThe following vulnerable instance'+s+' installed on the'+
      '\nremote host :\n'+
      info;
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}
if (info2)
{
  info2 -= " and ";
  if (" and " >< info2) be = "are";
  else be = "is";

  exit(0, "The host is not affected since Standard MultiPlugin "+info2+" "+be+" installed.");
}
else exit(0, "The Standard MultiPlugin plugin is not installed, and thus the host is not affected.");
