#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(44047);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_name(english:"PDF-XChange Detection");
  script_summary(english:"Checks if PDF-XChange/ PDF-XChange Viewer software is installed.");

  script_set_attribute(attribute:"synopsis", value:
"A software to create or view PDF files is installed on the remote
host.");
  script_set_attribute(attribute:"description", value:
"PDF-XChange or PDF-XChange Viewer a software to create or view PDF
files is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.docu-track.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

#
include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated"))  exit(1,"The 'SMB/Registry/Enumerated' KB item is not set to TRUE.");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Find where it's installed.
paths = make_array();

key = "SOFTWARE\Tracker Software\PDFViewer";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(value)) paths["PDF-XChange Viewer"] = value[1];

  RegCloseKey(handle:key_h);
}

# Look for PDFViewer SDK versions
# Figure out where the installer recorded information about it.

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  installstring = NULL;
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && "PDF-XChange PDF Viewer SDK" >< prod)
    {
      installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
      installstring = str_replace(find:"/", replace:"\", string:installstring);
      break;
    }
  }

  if(!isnull(installstring))
  {
    key_h = RegOpenKey(handle:hklm, key:installstring, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"InstallLocation");
      if (!isnull(value))
        paths["PDF-XChange PDF Viewer SDK"] = value[1] + "\Bin";

      RegCloseKey(handle:key_h);
    }
  }
}

# Try to extract PDF-XChange editions

edition  = NULL;
prod     = NULL;
prod_ver = NULL;

if(!isnull(list))
{
  installstring = NULL;
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && ereg(pattern:"^PDF-XChange[0-9\s]*($|Pro|Lite)[\s0-9]*$",string:prod))
    {
      if("Pro" >< prod) edition = " Pro";
      else if ("Lite" >< prod) edition = " Lite";
      else edition = " Standard";

      installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
      installstring = str_replace(find:"/", replace:"\", string:installstring);
      break;
    }
  }

  # Get the install location

  if(!isnull(installstring))
  {
    key_h = RegOpenKey(handle:hklm, key:installstring, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"InstallLocation");
      if (!isnull(value))
        paths["PDF-XChange" + edition] = value[1] ;

        value = RegQueryValue(handle:key_h, item:"DisplayVersion");
        if (!isnull(value))
        {
          prod_ver = value[1];
          if(ereg(pattern:"^[0-9.]+$",string:prod_ver))
          {
            prod_ver = split(prod_ver,sep:".",keep:FALSE);
            prod_ver = prod_ver[0];
          }
        }

      RegCloseKey(handle:key_h);
    }
  }
}

# Look for PDF-XChange

key = "SOFTWARE\Tracker Software";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  if(isnull(edition)) edition = " Standard";

  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    # e.g. PDF-XChange 4.0
    if (strlen(subkey) && subkey =~ "^PDF-XChange[0-9.\s]*$")
    {
      key2 = key + "\" + subkey + "\Drivers";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"InstallPath");
        if (!isnull(value)) paths["PDF-XChange" + edition] = value[1];

        RegCloseKey(handle:key2_h);
        if(!isnull(paths["PDF-XChange" + edition])) break;
      }
    }
  }
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);

info = "";

if(isnull(prod_ver))
  prod_ver = 4; # Assume version 4

foreach product (keys(paths))
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:paths[product]);

  if("PDF-XChange PDF Viewer SDK" >< product || "PDF-XChange Viewer" >< product)
    file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\PDFXCview.exe", string:paths[product]);
  else if (ereg(pattern:"^PDF-XChange (Standard|Pro)$",string:product))
    file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1OFFice2PDF.exe", string:paths[product]);

  # Special case for Lite editions
  # e.g pdfSaver4l.exe

  else if (ereg(pattern:"^PDF-XChange Lite$",string:product))
    file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1PDF-XChange Lite "+ prod_ver +"\pdfSaver" + prod_ver + "l.exe", string:paths[product]);

  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL,share);
  }

  fh = CreateFile(file:file,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING);

  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);

    if (!isnull(ver))
    {
      version = ver[0] + "." + ver[1] + "." + ver[2] + "." + ver[3];
      version_ui = ver[0] + "." + ver[1]  + " Build " + ver[2];

      set_kb_item(name:"SMB/Tracker_Software/"+ product + "/Installed", value:TRUE);
      set_kb_item(name:"SMB/Tracker_Software/"+ product + "/"+ version, value:paths[product]);

      register_install(
        app_name:product,
        path:paths[product],
        version:version,
        display_version:version_ui);

      info += '  Product Name  : ' + product + '\n' +
              '  Path          : ' + paths[product]+ '\n' +
              '  Version       : ' + version_ui + '\n' +
              '\n';
    }
  }
}

NetUseDel();

if(info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info,sep:'\n\n',keep:FALSE)) > 1) s = "s of PDF-XChange or PDF-XChange Viewer are";
      else s = " of PDF-XChange or PDF-XChange Viewer is";

    report = '\n' +
      'The following instance' + s + ' installed :' + '\n' +
      '\n' +
      info ;

    security_note(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_note(get_kb_item("SMB/transport"));
}
else
 exit(0,"PDF-XChange or PDF-XChange Viewer is not installed on the remote host.");

