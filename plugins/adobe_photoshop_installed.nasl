#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51188);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/04/11 14:45:47 $");

  script_name(english:"Adobe Photoshop Detection");
  script_summary(english:"Checks if Adobe Photoshop is installed.");

  script_set_attribute(attribute:"synopsis", value:
"A graphics editing application is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Adobe Photoshop, a graphics editing application, is installed on the
remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/photoshop.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");
include("smb_reg_query.inc");
include("obj.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Can't open socket on port "+port+".");

#session_init(socket:soc, hostname:name);

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

paths = make_list();

# Find where it's installed.
key = "SOFTWARE\Adobe\Photoshop";
subkeys = get_registry_subkeys(handle:hklm, key:key, wow:TRUE);

if (!empty_or_null(subkeys))
{
  foreach item (keys(subkeys))
  {
    foreach subkey (subkeys[item])
    {
      # Example: SOFTWARE\Adobe\Photoshop\12.0
      if (subkey !~ "^[0-9.]+$") continue;

      path = get_registry_value(handle:hklm, item:item + "\" + subkey + "\ApplicationPath");
      if (!empty_or_null(path)) paths = make_list(paths, path);
    }
  }
}

RegCloseKey(handle:hklm);

if (empty_or_null(paths)) audit(AUDIT_NOT_INST, "Adobe Photoshop");

info = '';

foreach loc (list_uniq(paths))
{
 # Grab the file version of file Photoshop.exe
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:loc);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Photoshop.exe", string:loc);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to "+share+" share.");
  }

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  ver          = NULL;
  product_name = NULL;

  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);

    ret = GetFileVersionEx(handle:fh);
    if (!isnull(ret)) children = ret['Children'];

    if (!isnull(children))
    {
      varfileinfo = children['VarFileInfo'];
      if (!isnull(varfileinfo))
      {
        translation =
         (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
          get_word (blob:varfileinfo['Translation'], pos:2);
        translation = tolower(convert_dword(dword:translation, nox:TRUE));
      }
      stringfileinfo = children['StringFileInfo'];
      if (!isnull(stringfileinfo) && !isnull(translation))
      {
        data = stringfileinfo[translation];
        if (isnull(data)) data = stringfileinfo[toupper(translation)];
        # Get product name
        # e.g. Adobe Photoshop CS5
        if (!isnull(data))
          product_name = data['ProductName'];
      }
    }
    CloseFile(handle:fh);
  }

  if(!isnull(ver))
  {
    version = join(ver, sep:".");
    version_ui = ver[0] + "." + ver[1] + "." + ver[2];

    if(isnull(product_name))
     product_name = 'Adobe Photoshop';

    set_kb_item(name:"SMB/Adobe_Photoshop/Installed", value:TRUE);
    set_kb_item(name:"SMB/Adobe_Photoshop/Version", value:version);
    set_kb_item(name:"SMB/Adobe_Photoshop/"+version+"/Version_UI", value:version_ui);
    set_kb_item(name:"SMB/Adobe_Photoshop/"+version+"/Product", value:product_name);
    set_kb_item(name:"SMB/Adobe_Photoshop/"+version+"/Path", value:loc);

    register_install(
      app_name:"Adobe Photoshop",
      path:loc,
      version:version,
      display_version:version_ui,
      extra:make_array("Product", product_name),
      cpe:"cpe:/a:adobe:photoshop");

    info +=
           '\n  Product : ' + product_name +
           '\n  Path    : ' + loc +
           '\n  Version : ' + version_ui + '\n';

    version =  version_ui = product_name = NULL;
  }
}

NetUseDel();

if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 4 ) s = "s of Adobe Photoshop are";
    else s = " of Adobe Photoshop is";

    report = '\n' +
      'The following instance' + s + ' installed :' + '\n' +
      info ;
    security_note(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_note(get_kb_item("SMB/transport"));
}
else exit(0,"Adobe Photoshop is not installed on the remote host.");
