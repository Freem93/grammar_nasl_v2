#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21608);
  script_version("$Revision: 1.1594 $");
  script_cvs_date("$Date: 2016/06/28 21:55:10 $");

  script_name(english:"NOD32 Antivirus Detection and Status");
  script_summary(english:"Checks for NOD32 Antivirus System.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"NOD32 Antivirus, a commercial antivirus software package for Windows,
is installed on the remote host. However, there is a problem with the
installation; either its services are not running or its engine and/or
virus definitions are out of date.");
  script_set_attribute(attribute:"see_also", value:"http://www.nod32.com/");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport", "SMB/Services/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("antivirus.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("install_func.inc");

# Connect to the remote registry.
get_kb_item_or_exit("SMB/registry_full_access");
get_kb_item_or_exit("SMB/Services/Enumerated");

login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Check if the software is installed.
path = NULL;
sigs_target_yyyymmdd = NULL;
sigs_target_update = NULL;

key = "SOFTWARE\Eset\Nod\CurrentVersion\Info";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(value))
   {
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:value[1]);
   }

  # Sig date is stored in the registry.
  value = RegQueryValue(handle:key_h, item:"CurrentVersion");
  if (!isnull(value))
  {
    sigs_target_update = ereg_replace(pattern:"^([0-9]+).*", string:value[1], replace:"\1");
    sigs_target_yyyymmdd = ereg_replace(pattern:"^.*\(([0-9]{8})\)", string:value[1], replace:"\1");
  }

  RegCloseKey (handle:key_h);
}

# nb:
# In new versions 3.667 and older, information is stored
# in different registry locations.

if ("Obsolete" >< path || isnull(path))
{
  key = "SOFTWARE\ESET\ESET Security\CurrentVersion\Info";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

   if (!isnull(key_h))
   {
     value = RegQueryValue(handle:key_h, item:"InstallDir");
     if (!isnull(value))
     {
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:value[1]);
     }

     # Sig date is stored in the registry.
     value = RegQueryValue(handle:key_h, item:"ScannerVersion");
     if (!isnull(value))
     {
      sigs_target_update = ereg_replace(pattern:"^([0-9]+).*", string:value[1], replace:"\1");
      sigs_target_yyyymmdd = ereg_replace(pattern:"^.*\(([0-9]{8})\)", string:value[1], replace:"\1");
     }

     RegCloseKey (handle:key_h);
   }
}
RegCloseKey(handle:hklm);

# If it is, get the application's version number.
if (!isnull(path))
{
  NetUseDel(close:FALSE);

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

  if ("SOFTWARE\ESET\ESET Security\CurrentVersion\Info" >< key)
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\egui.exe", string:path);
  else
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\nod32.exe", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {
    fh = CreateFile(
      file:exe,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );

    if (!isnull(fh))
    {
      version = GetFileVersion(handle:fh);
      ver = string(version[0], ".", version[1], ".", version[2], ".", version[3]);
      CloseFile(handle:fh);
    }
  }
}
NetUseDel();

if (isnull(path) || isnull(sigs_target_yyyymmdd) || isnull(ver)) audit(AUDIT_NOT_INST, "NOD32 Antivirus");

set_kb_item(name:"Antivirus/NOD32/installed", value:TRUE);
set_kb_item(name:"Antivirus/NOD32/version", value:ver);
set_kb_item(name:"Antivirus/NOD32/path", value:path);
set_kb_item(name:"Antivirus/NOD32/sigs", value:string(sigs_target_update, " (", sigs_target_yyyymmdd, ")"));

register_install(
  app_name:"NOD32 Antivirus",
  path:path,
  version:ver,
  extra:make_array("sigs", string(sigs_target_update, " (", sigs_target_yyyymmdd, ")")));

# Generate report
trouble = 0;

# - general info.
report = "The NOD32 Antivirus System is installed on the remote host :

  Version:           " + ver + "
  Installation path: " + path + "
  Virus signatures:  " + sigs_target_update + " (" + sigs_target_yyyymmdd + ")

";

# - sigs out-of-date?
info = get_av_info("nod32");
if (isnull(info)) exit(1, "Failed to get NOD32 Antivirus info from antivirus.inc.");
sigs_vendor_yyyymmdd = info["sigs_vendor_yyyymmdd"];

if (sigs_target_yyyymmdd =~ "^2[0-9][0-9][0-9][01][0-9][0-3][0-9]")
{
  if (int(sigs_target_yyyymmdd) < int(sigs_vendor_yyyymmdd)) {
    report += "The virus signatures on the remote host are out-of-date - the last known
update from the vendor is " + sigs_vendor_yyyymmdd + ".

";
    trouble++;
  }
}

# - services running.
services = get_kb_item("SMB/svcs");
if (services)
{
  if (
    ("ekrn" >!< services) &&
    (
      "NOD32 Kernel Service" >!< services &&
      "NOD32km" >!< services
    )
  )
  {
    report += 'The remote NOD32 service is not running.\n\n';
    trouble++;
  }
}
else
{
  report += 'Nessus was unable to retrieve a list of running services from the host.\n\n';
  trouble++;
}

if (trouble) report += "As a result, the remote host might be infected by viruses.";

if (trouble) {
  report = string(
    "\n",
    report
  );
  security_hole(port:port, extra:report);
}
else {
  # nb: antivirus.nasl uses this in its own report.
  set_kb_item (name:"Antivirus/NOD32/description", value:report);
  exit(0, "Detected NOD32 Antivirus with no known issues to report.");
}
