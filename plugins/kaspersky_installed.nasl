#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20284);
  script_version("$Revision: 1.1821 $");
  script_cvs_date("$Date: 2017/01/19 20:44:47 $");

  script_name(english:"Kaspersky Anti-Virus Detection and Status");
  script_summary(english:"Checks for Kaspersky Anti-Virus.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"Kaspersky Anti-Virus, a commercial antivirus software package for
Windows, is installed on the remote host. However, there is a problem
with the installation; either its services are not running or its
engine and/or virus definitions are out of date.");
  script_set_attribute(attribute:"see_also", value:"http://www.kaspersky.com/");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kaspersky_lab:kaspersky_anti-virus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport", "SMB/Services/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("antivirus.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("install_func.inc");

# Connect to the remote registry.
get_kb_item_or_exit("SMB/registry_full_access");
get_kb_item_or_exit("SMB/Services/Enumerated");

name    = kb_smb_name();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, 'IPC$');
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Check if the software is installed.
base_dir = NULL;
name = NULL;
path = NULL;
prodinfo = NULL;
sig_path = NULL;
upd_cfg = NULL;
ver = NULL;

# - KAV 15
prod++;
prod_subkeys[prod] = "KasperskyLab\AVP15.0.0\environment";
name_subkeys[prod] = "ProductName";
path_subkeys[prod] = "ProductRoot";
ver_subkeys[prod]  = "ProductVersion";
# - KAV 14
prod++;
prod_subkeys[prod] = "KasperskyLab\protected\AVP14.0.0\environment";
name_subkeys[prod] = "ProductName";
path_subkeys[prod] = "ProductRoot";
ver_subkeys[prod]  = "ProductVersion";
# - KAV 7.0 (Internet Security / Anti-Virus / Anti-Virus for Windows Workstations / Anti-Virus for Windows Servers)
prod++;
prod_subkeys[prod] = "KasperskyLab\protected\AVP7\environment";
name_subkeys[prod] = "ProductName";
path_subkeys[prod] = "ProductRoot";
ver_subkeys[prod]  = "ProductVersion";
# - KAV 6.0 (Internet Security / Anti-Virus / Anti-Virus for Windows Workstations / Anti-Virus for Windows Servers)
prod++;
prod_subkeys[prod] = "KasperskyLab\AVP6\Environment";
name_subkeys[prod] = "ProductName";
path_subkeys[prod] = "ProductRoot";
ver_subkeys[prod]  = "ProductVersion";
# - KAV for Windows File Servers
prod++;
prod_subkeys[prod] = "Microsoft\Windows\CurrentVersion\Uninstall\{1A694303-9A42-43A8-A831-50F86C64EDF0}";
name_subkeys[prod] = "DisplayName";
path_subkeys[prod] = "InstallLocation";
ver_subkeys[prod]  = "DisplayVersion";
# - KAV for Workstations
prod++;
prod_subkeys[prod] = "KasperskyLab\InstalledProducts\Kaspersky Anti-Virus for Windows Workstations";
name_subkeys[prod] = "Name";
path_subkeys[prod] = "Folder";
ver_subkeys[prod]  = "Version";
# - KAV Personal / KAV Personal Pro
prod++;
prod_subkeys[prod] = "KasperskyLab\InstalledProducts\Kaspersky Anti-Virus Personal";
name_subkeys[prod] = "Name";
path_subkeys[prod] = "Folder";
ver_subkeys[prod]  = "Version";
# - KAV / KAV IS 2010
prod++;
prod_subkeys[prod] = "KasperskyLab\protected\AVP9\environment";
name_subkeys[prod] = "ProductName";
path_subkeys[prod] = "ProductRoot";
ver_subkeys[prod]  = "ProductVersion";

# More recent versions use a more predictable registry structure
# Look for evidence of the product in the subkeys and use that to
# determine the correct Registry hive to search
arch = get_kb_item("SMB/ARCH");
key = "SOFTWARE\KasperskyLab\protected";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (isnull(key_h))
{
  key = "SOFTWARE\KasperskyLab\"; # New key format introduced in KTS/PURE
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
}
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  if (!isnull(info))
  {
    for (i=0; i < info[1]; i++)
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      if (strlen(subkey) && subkey =~ '^(AVP|KES|PURE)([0-9]+|[0-9\\.]+)(SP[0-9]+)?$')
      {
        key2 = key + '\\' + subkey + "\environment";
        # During the un-install process for some KASP products, artifact
        # keys can be left over, we need to verify key2 actually exists
        # before stopping our search, it maybe one of these artifacts
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if(isnull(key2_h))
        {
          key2 = NULL;
          RegCloseKey(handle:key2_h);
        }
        else
        {
          RegCloseKey(handle:key2_h);
          break;
        }
      }
    }
  }
  RegCloseKey(handle:key_h);
}

if (!key2 && arch == 'x64')
{
  # In more recent versions of the software, there is a registry hive
  # under SOFTWARE\KasperskyLab\protected so we have to also check
  # the Wow6432Node.
  key = "SOFTWARE\Wow6432Node\KasperskyLab\protected";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (isnull(key_h))
  {
    key = "SOFTWARE\Wow6432Node\KasperskyLab\"; # New key format introduced in KTS/PURE
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  }
  if (!isnull(key_h))
  {
    info = RegQueryInfoKey(handle:key_h);
    if (!isnull(info))
    {
      for (i=0; i < info[1]; i++)
      {
        subkey = RegEnumKey(handle:key_h, index:i);
        if (strlen(subkey) && subkey =~ '^(AVP|KES|PURE)([0-9]+|[0-9\\.]+)(SP[0-9]+)?$')
        {
          key2 = key + '\\' + subkey + "\environment";
          # During the un-install process for some KASP products, artifact
          # keys can be left over, we need to verify key2 actually exists
          # before stopping our search, it maybe one of these artifacts
          key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
          if(isnull(key2_h))
          {
            key2 = NULL;
            RegCloseKey(handle:key2_h);
          }
          else
          {
            RegCloseKey(handle:key2_h);
            break;
          }
        }
      }
    }
  }
  RegCloseKey(handle:key_h);
}

# If we found the correct registry hive, look for the product
# information
if (key2)
{
  key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
  if (!isnull(key2_h))
  {
    value = RegQueryValue(handle:key2_h, item:"ProductName");
    if (!isnull(value))
    {
      name = value[1];
      # get rid of version info in the name
      name = ereg_replace(string:name, pattern:" [0-9.]+", replace:"");
    }

    value = RegQueryValue(handle:key2_h, item:"ProductRoot");
    if (!isnull(value)) path = ereg_replace(string:value[1], pattern:"\$", replace:"");

    value = RegQueryValue(handle:key2_h, item:"ProductVersion");
    if (!isnull(value)) ver = value[1];

    # Figure out where to look for signature info
    value = RegQueryValue(handle:key2_h, item:"UpdateRoot");
    if (!isnull(value))
    {
      upd_cfg = value[1];
      upd_cfg = ereg_replace(pattern:"^.+/(.+\.xml)$", replace:"\1", string:upd_cfg);
    }

    data_dir = "%DataFolder%";
    i = 0;
    while (match = eregmatch(pattern:"%([a-zA-Z]+)%", string:data_dir))
    {
      s = match[1];
      value = RegQueryValue(handle:key2_h, item:s);
      if (!isnull(value))
        data_dir = str_replace(find:"%"+s+"%", replace:value[1], string:data_dir);
      else break;

      # limit how many times we'll loop
      if (++i > 5) break;
    }
    if (!isnull(upd_cfg) && !isnull(data_dir)) upd_cfg = data_dir + '\\' + upd_cfg;

    base_dir = "%Base%";
    i = 0;
    while (match = eregmatch(pattern:"%([a-zA-Z]+)%", string:base_dir))
    {
      s = match[1];
      value = RegQueryValue(handle:key2_h, item:s);
      if (!isnull(value))
        base_dir = str_replace(find:"%"+s+"%", replace:value[1], string:base_dir);
      else break;

      # limit how many times we'll loop
      if (++i > 5) break;
    }
    if (base_dir == "%Base%")
    {
      base_dir = "%Bases%";
      i = 0;

      while (match = eregmatch(pattern:"%([a-zA-Z]+)%", string:base_dir))
      {
        s = match[1];
        value = RegQueryValue(handle:key2_h, item:s);
        if (!isnull(value))
          base_dir = str_replace(find:"%"+s+"%", replace:value[1], string:base_dir);
        else break;

        # limit how many times we'll loop
        if (++i > 5) break;
      }
    }
    RegCloseKey(handle:key2_h);
  }

  if (isnull(data_dir) || isnull(base_dir))
  {
    # Some products point to it in the registry
    key3 = "SOFTWARE\KasperskyLab\Components\10a\LastSet";
    key3_h = RegOpenKey(handle:hklm, key:key3, mode:MAXIMUM_ALLOWED);
    if (!isnull(key3_h))
    {
      value = RegQueryValue(handle:key3_h, item:"Directory");
      if (!isnull(value)) sig_path = ereg_replace(string:value[1], pattern:"\$", replace:"");
    }
    RegCloseKey(handle:key3_h);

    # Some products point to it from SS_PRODINFO.xml
    key2 = "SOFTWARE\KasperskyLab\Components\34";
    key2_h = RegOpenKey(handle:hklm, key:key3, mode:MAXIMUM_ALLOWED);
    if (!isnull(key3_h))
    {
      value = RegQueryValue(handle:key3_h, item:"SS_PRODINFO");
      if (!isnull(value)) prodinfo = ereg_replace(string:value[1], pattern:"\$", replace:"");
    }
    RegCloseKey(handle:key3_h);
  }
  RegCloseKey(handle:key2_h);
}

# If we couldn't find the product info, it is probably an older version
# Use the pre-defined arrays to try to find product information
if (isnull(name) || isnull(path) || isnull(ver))
{
  foreach prod (keys(prod_subkeys))
  {
    key = "SOFTWARE\" + prod_subkeys[prod];
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

    if (!isnull(key_h)) {
      value = RegQueryValue(handle:key_h, item:name_subkeys[prod]);
      if (!isnull(value))
      {
        name = value[1];
        # get rid of version info in the name.
        name = ereg_replace(string:name, pattern:" [0-9.]+", replace:"");
      }

      value = RegQueryValue(handle:key_h, item:path_subkeys[prod]);
      if (!isnull(value)) path = ereg_replace(string:value[1], pattern:"\$", replace:"");

      value = RegQueryValue(handle:key_h, item:ver_subkeys[prod]);
      if (!isnull(value)) ver = value[1];

      # Figure out where to look for signature info.
      #
      # - KAV 15 / 14 / 2010 / 7.0 / 6.0
      if (
        prod_subkeys[prod] == "KasperskyLab\AVP15.0.0\environment" ||
        prod_subkeys[prod] == "KasperskyLab\protected\AVP14.0.0\environment" ||
        prod_subkeys[prod] == "KasperskyLab\protected\AVP9\environment" ||
        prod_subkeys[prod] == "KasperskyLab\protected\AVP7\environment" ||
        prod_subkeys[prod] == "KasperskyLab\AVP6\Environment"
      )
      {
        # Figure out where the update config is.
        value = RegQueryValue(handle:key_h, item:"UpdateRoot");
        if (!isnull(value))
        {
          upd_cfg = value[1];
          upd_cfg = ereg_replace(pattern:"^.+/(.+\.xml)$", replace:"\1", string:upd_cfg);
        }

        data_dir = "%DataFolder%";
        i = 0;
        while (match = eregmatch(pattern:"%([a-zA-Z]+)%", string:data_dir))
        {
          s = match[1];
          value = RegQueryValue(handle:key_h, item:s);
          if (!isnull(value))
            data_dir = str_replace(
              find:"%" + s + "%",
              replace:value[1],
              string:data_dir
            );
          else break;

          # limit how many times we'll loop.
          if (++i > 5) break;
        }
        if (!isnull(upd_cfg) && !isnull(data_dir)) upd_cfg = data_dir + "\" + upd_cfg;

        base_dir = "%Bases%";
        i = 0;
        while (match = eregmatch(pattern:"%([a-zA-Z]+)%", string:base_dir))
        {
          s = match[1];
          value = RegQueryValue(handle:key_h, item:s);
          if (!isnull(value))
            base_dir = str_replace(
              find:"%" + s + "%",
              replace:value[1],
              string:base_dir
            );
          else break;

          # limit how many times we'll loop.
          if (++i > 5) break;
        }
      }
      else
      {
        # some products point to it in the registry.
        key2 = "SOFTWARE\KasperskyLab\Components\10a\LastSet";
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if (!isnull(key2_h))
        {
          value = RegQueryValue(handle:key2_h, item:"Directory");
          if (!isnull(value)) sig_path = ereg_replace(string:value[1], pattern:"\$", replace:"");
        }
        RegCloseKey(handle:key2_h);

        # some products point to it from SS_PRODINFO.xml.
        key2 = "SOFTWARE\KasperskyLab\Components\34";
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if (!isnull(key2_h))
        {
          value = RegQueryValue(handle:key2_h, item:"SS_PRODINFO");
          if (!isnull(value)) prodinfo = ereg_replace(string:value[1], pattern:"\$", replace:"");
        }
        RegCloseKey(handle:key2_h);
      }
      RegCloseKey(handle:key_h);

      # We found a product so we're done.
      break;
    }
  }
  RegCloseKey(handle:hklm);
  NetUseDel(close:FALSE);
}

if (isnull(name) || isnull(path) || isnull(ver))
{
  NetUseDel();
  audit(AUDIT_NOT_INST,"Kaspersky Antivirus");
}

set_kb_item(name:"Antivirus/Kaspersky/installed", value:TRUE);
set_kb_item(name:"Antivirus/Kaspersky/" + name, value:ver + " in " + path);

# Figure out where signature information is stored.
update_date = NULL;

# - KAV 7.0 / 6.0
if (!isnull(upd_cfg) && !isnull(base_dir))
{
  # First, read the main updates file.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:upd_cfg);
  xml_file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:upd_cfg);

  av_upd = NULL;

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {
    fh = CreateFile(
      file:xml_file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      contents = ReadFile(handle:fh, offset:0, length:10240);
      contents = str_replace(string:contents, find:raw_string(0x00), replace:"");

      if (("AVP14.0.0" >< upd_cfg || "AVP15.0" >< upd_cfg || "KES10SP1" >< upd_cfg) && 'List="KDB,EMU' >< contents)
      {
        match = eregmatch(pattern:'List="KDB,EMU.+\\.xml\\|([0-9]+ [0-9]+)', string:contents);
        if (!isnull(match)) update_date = match[1];
      }
      else if (contents && 'UpdateDate="' >< contents)
      {
        contents = strstr(contents, 'UpdateDate="') - 'UpdateDate="';
        contents = contents - strstr(contents, '"');
        update_date = contents;
      }
      else if("AVP9" >< upd_cfg && 'ComponentID="VLNS,KDBI386"' >< contents)
      {
        # nb: File referenced by AVS component does not exist
        #     in AVP9, therefore we use file referenced by
        #     VLNS,KDBI386 to extract update date, which is
        #     accurate.
        {
          contents = strstr(contents, 'ComponentID="VLNS,KDBI386"');
          if (contents) contents = contents - strstr(contents, ">");
          if (contents && 'Filename="' >< contents)
          {
            av_upd = strstr(contents, 'Filename="') - 'Filename="';
            av_upd = av_upd - strstr(av_upd, '"');
          }
         }
      }
      else if ('ComponentID="AVS"' >< contents)
      {
        contents = strstr(contents, 'ComponentID="AVS"');
        if (contents) contents = contents - strstr(contents, ">");
        if (contents && 'Filename="' >< contents)
        {
          av_upd = strstr(contents, 'Filename="') - 'Filename="';
          av_upd = av_upd - strstr(av_upd, '"');
        }
      }
      # AVP 16, KES10SP1, AVP 17 (Kaspersky Total Security 17)
      else if (
        (
         'AVP17' >< upd_cfg ||
         'AVP16' >< upd_cfg ||
         "KES10SP1" >< upd_cfg
        ) &&
        'CompID="KDBEFI"' >< contents
      )
      {
        tag_open = stridx(contents, "<Update");
        tag_close = stridx(contents, ">");
        if (tag_open >= 0 && tag_close > tag_open)
        {
          contents = substr(contents, tag_open, tag_close);
          match = eregmatch(pattern:'Date="([0-9]+ [0-9]+)"', string:contents);
          if (!isnull(match))
            update_date = match[1];
        }
      }
      CloseFile(handle:fh);
    }
    NetUseDel(close:FALSE);
  }

  # Now grab the AV update file.
  if (!isnull(av_upd) && isnull(update_date))
  {
    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:base_dir);
    xml_file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\"+av_upd, string:base_dir);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc == 1)
    {
      fh = CreateFile(
        file:xml_file,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );
      if (!isnull(fh))
      {
        contents = ReadFile(handle:fh, offset:0, length:10240);
        contents = str_replace(string:contents, find:raw_string(0x00), replace:"");

        if ('UpdateDate="' >< contents)
        {
          contents = strstr(contents, 'UpdateDate="') - 'UpdateDate="';
          if (contents) contents = contents - strstr(contents, ">");
          if (contents && '"' >< contents)
          {
            update_date = contents - strstr(contents, '"');
          }
        }
        CloseFile(handle:fh);
      }
      NetUseDel(close:FALSE);
    }
  }
}
else
{
  if (prodinfo)
  {
    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:prodinfo);
    prodinfo_file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:prodinfo);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc == 1) {
      fh = CreateFile(
        file:prodinfo_file,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );
      if (!isnull(fh))
      {
        contents = ReadFile(handle:fh, offset:0, length:10240);
        contents = str_replace(string:contents, find:raw_string(0x00), replace:"");

        # Isolate the base folder path.
        sig_path = strstr(contents, "BaseFolder");
        if (sig_path)
        {
          len = ord(sig_path[11]);
          if (sig_path) sig_path = substr(sig_path, 12, 12+len-1);
        }

        CloseFile(handle:fh);
      }
      NetUseDel(close:FALSE);
    }
  }

  # Make an assumption if we couldn't determine it.
  if (!sig_path)
  {
    v = split(ver, sep:'.', keep:FALSE);
    sig_path = "C:\Documents and Settings\All Users\Application Data\" +
               name + "\" +
               v[0] + "." + v[1] +
               "\Bases";
  }

  # Read signature date from the file KAVSET.XML.
  #
  # nb: this is stored typically in a hidden directory, in case one's
  #     simply looking for it.
  share = ereg_replace(pattern:"(^[A-Za-z]):.*", replace:"\1$", string:sig_path);
  xml_file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\kavset.xml", string:sig_path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {
    fh = CreateFile(
      file:xml_file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      contents = ReadFile(handle:fh, offset:0, length:256);

      # Get the date from the update_date XML block.
      update_date = strstr(contents, "Updater/update_date");
      if (update_date) update_date = update_date - strstr(update_date, '" />');
      if (update_date) update_date = strstr(update_date, 'Value="');
      if (update_date) update_date = update_date - 'Value="';
    }
    CloseFile(handle:fh);
  }
}
NetUseDel();

if (!isnull(update_date) && update_date =~ "^[0-9]+ [0-9]+$")
{
  day   = substr(update_date, 0, 1);
  month = substr(update_date, 2, 3);
  year  = substr(update_date, 4, 7);
  sigs_target = month + "/" + day + "/" + year;
}
else sigs_target = "unknown";
set_kb_item(name:"Antivirus/Kaspersky/sigs", value:sigs_target);

# Generate report
trouble = 0;

# - general info.
report = "Kaspersky Anti-Virus is installed on the remote host :

  Product name      : " + name + "
  Version           : " + ver + "
  Installation path : " + path + "
  Virus signatures  : " + sigs_target + "

";

register_install(
  app_name : name,
  version  : ver,
  path     : path,
  cpe      : "cpe:/a:kaspersky_lab:kaspersky_anti-virus"
);

# - sigs out-of-date?
info = get_av_info("kaspersky");
if (isnull(info)) exit(1, "Failed to get Kaspersky Anti-Virus info from antivirus.inc.");
sigs_vendor_yyyymmdd = info["sigs_vendor_yyyymmdd"];

out_of_date = 1;
# nb: out_of_date will be 1 if sigs_target == "unknown".
if (sigs_target =~ "[0-9][0-9]/[0-9][0-9]/[0-9][0-9][0-9][0-9]")
{
  a = split(sigs_target, sep:"/", keep:0);
  sigs_target_yyyymmdd = a[2] + a[0] + a[1];

  if (int(sigs_target_yyyymmdd) >= (int(sigs_vendor_yyyymmdd) - 1))
    out_of_date = 0;
}
if (out_of_date)
{
  sigs_vendor_mmddyyyy =
    substr(sigs_vendor_yyyymmdd, 4, 5) +
    "/" +
    substr(sigs_vendor_yyyymmdd, 6, 7) +
    "/" +
    substr(sigs_vendor_yyyymmdd, 0, 3);

  report += "The virus signatures on the remote host are out-of-date - the last
known update from the vendor is " + sigs_vendor_mmddyyyy + "

";
  trouble++;
}

# - services running.
services = get_kb_item("SMB/svcs");
if (services)
{
  if(
    # Kaspersky Endpoint Security
    "Kaspersky Endpoint Security" >!< services &&
    # Kaspersky Internet Security
    "Kaspersky Internet Security" >!< services &&
    "AVP" >!< services &&
    "avp" >!< services &&
    # others
    "Kaspersky Anti-Virus" >!< services &&
    "kavsvc" >!< services
  )
  {
   report += 'The remote Kaspersky Anti-Virus service is not running.\n\n';
   trouble++;
  }
}
else
{
  report += 'Nessus was unable to retrieve a list of running services from the host.\n\n';
  trouble++;
}

if (trouble)
{
  report =
    '\n'+
    report +
    "As a result, the remote host might be infected by viruses.";

  security_hole(port:port, extra:report);
}
else
{
  # nb: antivirus.nasl uses this in its own report.
  set_kb_item (name:"Antivirus/Kaspersky/description", value:report);
  exit(0, "Detected Kaspersky Anti-Virus with no known issues to report.");
}
