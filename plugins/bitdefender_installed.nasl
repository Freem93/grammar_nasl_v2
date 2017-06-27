#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24232);
  script_version("$Revision: 1.1645 $");
  script_cvs_date("$Date: 2016/06/28 18:08:40 $");

  script_name(english:"BitDefender Antivirus Detection and Status");
  script_summary(english:"Checks for BitDefender.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"BitDefender, a commercial antivirus software package for Windows, is
installed on the remote host. However, there is a problem with the
installation; either its services are not running or its engine and/or
virus definitions are out of date.");
  script_set_attribute(attribute:"see_also", value:"http://www.bitdefender.com/");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bitdefender:antivirus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

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

login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();
if (!port) port = 139;

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

# Grab info about the software itself and its updater.
prod_name = NULL;
prod_path = NULL;
prod_ver = NULL;
update_path = NULL;

# - for BitDefender Antivirus 2009 and BitDefender Internet Security.
key = "SOFTWARE\BitDefender\Livesrv";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Path_Antivirus");
  if (!isnull(value))
  {
    prod_path = value[1];
    prod_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:prod_path);
  }
  else
  {
    value = RegQueryValue(handle:key_h, item:"Path_InternetSecurity");
    if (!isnull(value))
    {
      prod_path = value[1];
      prod_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:prod_path);
    }
  }
  RegCloseKey(handle:key_h);
}
# - for BitDefender Antivirus 2012 and later
if (isnull(prod_path))
{
  key = "SOFTWARE\BitDefender";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"InstallDir");
    if (!isnull(value))
      prod_path = value[1];
  }
  RegCloseKey(handle:key_h);
}

if (!isnull(prod_path))
{
  key = "SOFTWARE\BitDefender\About";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"ProductName");
    if (!isnull(value)) prod_name = value[1];

    value = RegQueryValue(handle:key_h, item:"ProductVersion");
    if (!isnull(value)) prod_ver = value[1];

    RegCloseKey(handle:key_h);
  }
  if (isnull(prod_name))
  {
    key = "SOFTWARE\BitDefender\BitDefender Desktop\Maintenance\Antivirus";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"ProductName");
      if (!isnull(value)) prod_name = value[1];

      value = RegQueryValue(handle:key_h, item:"ProductVersion");
      if (!isnull(value)) prod_ver = value[1];

      RegCloseKey(handle:key_h);
    }
  }

  key = "SOFTWARE\BitDefender\BitDefender Threat Scanner";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"EnginesFolder");
    if (!isnull(value))
    {
      update_path = value[1];
      update_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:update_path);

      RegCloseKey(handle:key_h);
    }
  }
}
else
{
  key = "SOFTWARE\Softwin\BitDefender Desktop\Maintenance\Install";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"InstallDir");
    if (!isnull(value))
    {
      prod_path = value[1];
      prod_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:prod_path);
    }
    RegCloseKey(handle:key_h);
  }

  if (!isnull(prod_path))
  {
    key = "SOFTWARE\Softwin";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"BitDefender Scan Server");
      if (!isnull(value))
      {
        update_path = value[1];
        update_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:update_path);
      }
      RegCloseKey(handle:key_h);
    }
  }
}
RegCloseKey(handle:hklm);
if (isnull(prod_path) || isnull(update_path))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, 'BitDefender Antivirus');
}
NetUseDel(close:FALSE);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:prod_path);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

# If necessary, retrieve info about the product.
if (isnull(prod_name) || isnull(prod_ver))
{
  file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\status.ini", string:prod_path);

  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    contents = ReadFile(handle:fh, offset:0, length:10240);
    if (contents)
    {
      foreach line (split(contents, keep:FALSE))
      {
        if ("IDS_BITDEFENDER_PROF" >< line && isnull(prod_name))
        {
          prod_name = ereg_replace(pattern:'^.+[ \t]*=[ \t]*"(.+)"$', replace:"\1", string:line);
        }
        else if ("IDS_BUILD_PROF" >< line && isnull(prod_ver))
        {
          prod_ver = ereg_replace(pattern:'^.+[ \t]*=[ \t]*"(.+)"$', replace:"\1", string:line);
        }

        if (!isnull(prod_name) && !isnull(prod_ver)) break;
      }
    }
    CloseFile(handle:fh);
  }
}
if (isnull(prod_name)) prod_name = "unknown";
if (isnull(prod_ver)) prod_ver = "unknown";

# Retrieve info about the virus signatures and engine.
sigs = "unknown";
sigs_gmt = "unknown";
last_update = "unknown";
engine = "unknown";
fsigs = "unknown";
fsigs_gms = "unknown";
flast_update = "unknown";
fengine = "unknown";

dirpat = ereg_replace(pattern:'^[A-Za-z]:(.*)\\\\.*', replace:"\1\Antivirus_*", string:update_path);

retx = FindFirstFile(pattern:dirpat);
while (!isnull(retx[1]))
{
  if ((retx[1] != '.' && retx[1] != '..') && retx[1] =~ '^Antivirus_[0-9]+_[0-9]+$')
  {
    file = (dirpat - 'Antivirus_*') + retx[1] + "\Plugins\update.txt";

    fh = CreateFile(
      file:file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (isnull(fh))
    {
      debug_print('Couldn\'t open file \''+(share - '$')+file+'.');
    }
    else
    {
      contents = ReadFile(handle:fh, offset:0, length:256);
      if (contents)
      {
        foreach line (split(contents, keep:FALSE))
        {
          if ("Signature number:" >< line)
          {
            fsigs = ereg_replace(pattern:"^.*Signature number[ \t]*:[ \t]*([0-9]+)$", replace:"\1", string:line);
          }
          else if ("Update time:" >< line)
          {
            flast_update = ereg_replace(pattern:"^.*Update time[ \t]*:[ \t]*(.+)$", replace:"\1", string:line);
          }
          else if ("Version:" >< line)
          {
            fengine = ereg_replace(pattern:"^.*Version[ \t]*:[ \t]*([0-9.]+)$", replace:"\1", string:line);
          }
          else if ("Update time GMT:" >< line)
          {
            fsigs_gmt = ereg_replace(pattern:"^.*Update time GMT[ \t]*:[ \t]*([0-9]+)$", replace:"\1", string:line);
          }

          if (fsigs != "unknown" && flast_update != "unknown" && fengine != "unknown" && fsigs_gmt != "unknown")
          {
            if (fsigs_gmt > sigs_gmt || sigs_gmt == 'unknown')
            {
              sigs = fsigs;
              last_update = flast_update;
              engine = fengine;
              sigs_gmt = fsigs_gmt;
            }
            break;
          }
        }
      }
      CloseFile(handle:fh);
    }
  }
  retx = FindNextFile(handle:retx);
}
NetUseDel();

# Save info in the KB.
kb_base = "Antivirus/BitDefender";
set_kb_item(name:kb_base+"/installed", value:TRUE);
set_kb_item(name:kb_base+"/Product", value:prod_name);
set_kb_item(name:kb_base+"/Path", value:prod_path);
set_kb_item(name:kb_base+"/Version", value:prod_ver);
set_kb_item(name:kb_base+"/Sigs", value:sigs);
set_kb_item(name:kb_base+"/Sigs_Update", value:last_update);
set_kb_item(name:kb_base+"/Sigs_Update_GMT", value:sigs_gmt);
set_kb_item(name:kb_base+"/Engine", value:engine);
register_install(
  app_name:'BitDefender Antivirus',
  path:prod_path,
  version:prod_ver,
  cpe:"cpe:/a:bitdefender:antivirus");

# Generate report
trouble = 0;

# - general info.
report = "BitDefender is installed on the remote host :

  Product name      : " + prod_name + "
  Version           : " + prod_ver + "
  Installation path : " + prod_path + "
  Signature number  : " + sigs + "
  Signature update  : " + last_update + "
  Engine            : " + engine + "

";

# - sigs out-of-date?
info = get_av_info("bitdefender");
if (isnull(info)) exit(1, "Failed to get BitDefender antivirus info from antivirus.inc.");
sigs_vendor = info["sigs_vendor"];
sigs_gmt_vendor = info["sigs_gmt_vendor"];
if (
  (sigs_gmt == "unknown" || int(sigs_gmt) < int(sigs_gmt_vendor)) &&
  (sigs == "unknown" || int(sigs) != int(sigs_vendor))
)
{
  report += "
The virus signatures on the remote host are out-of-date - the last
known update from the vendor is signature number " + sigs_vendor + ".

";
  trouble++;
}


# - services running.
services = tolower(get_kb_item("SMB/svcs"));
if (services)
{
  running = FALSE;

  if (
    ("[ vsserv ]" >< services || "bitdefender virus shield" >< services) &&
    (
      (
       ("[ livesrv ]"  >< services || "[ updatesrv ]"  >< services) ||
       "bitdefender desktop update" >< services) ||
      (
        ("[ xcomm ]"  >< services || "bitdefender communicator" >< services) &&
        ("[ bdss ]"   >< services || "bitdefender scan server" >< services)
      )
    )
  ) running = TRUE;

  if (!running)
  {
    report += 'At least one of the BitDefender services is not running.\n\n';
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
  report += "As a result, the remote host might be infected by viruses.";

  report = string(
    "\n",
    report
  );
  security_hole(port:port, extra:report);
}
else
{
  # nb: antivirus.nasl uses this in its own report.
  set_kb_item(name:"Antivirus/BitDefender/description", value:report);
  exit(0, "Detected BitDefender Antivirus with no known issues to report.");
}
