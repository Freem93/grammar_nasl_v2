#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38973);
  script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_bugtraq_id(35144);

  script_name(english:"Avira AntiVir RAR/CAB/ZIP/LH Scan Evasion");
  script_summary(english:"Checks the version of multiple Avira AntiVir Products");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an antivirus application that is affected
by a file evasion vulnerability.");

  script_set_attribute(attribute:"description", value:
"The remote host is running an Avira AntiVir product. The scan engine
of the installed product is earlier than 7.9.0.180 / 8.2.0.180. Such
versions reportedly fail to properly inspect specially crafted
RAR/CAB/ZIP/LH files. An attacker could embed code in such files in
order to circumvent detection by antivirus software.");

  script_set_attribute(attribute:"see_also", value:"http://forum.avira.com/wbb/index.php?page=Thread&threadID=91375");

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/503914/30/0/threaded" );

  script_set_attribute(attribute:"solution", value:
"Use the Avira update feature to upgrade the scan engine to 7.9.0.180 /
8.2.0.180 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/registry_full_access");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

# Connect to the appropriate share
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name      = kb_smb_name();
port      = kb_smb_transport();
#if (!get_port_state(port)) exit(0);
login     = kb_smb_login();
pass      = kb_smb_password();
domain    = kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(0);

report = NULL;
s = 0;

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
    exit(0);
}

# Connect to remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
    exit(0);
}

# Grab installation path from the registry
paths = make_array();

prods = make_array(
  "SOFTWARE\H+BEDV\AntiVir Workstation", "AntiVir Windows Workstation",
  "SOFTWARE\Avira\Premium Security Suite", "Premium Security Suite",
  "SOFTWARE\Avira\AntiVir Server", "AntiVir Windows Server",
  "SOFTWARE\Avira\AntiVir Desktop", "AntiVir Windows Desktop"
);
foreach key (keys(prods))
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Path");
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:value[1]);
    prod = prods[key];
    paths[prod] = path;
  }
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);

# If it is installed

if (max_index(keys(paths)) > 0)
{
  foreach prod (keys(paths))
  {
    path = paths[prod];
    contents = NULL;

    # Look at avewin32.dll for the scan engine version
    #In the newer versions of Avira, avewin32.dll is gone
    #Version info can still be found in aeset.dat which is
    #updated with every update

    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
    engine = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\avewin32.dll", string:path);
    engine_2 = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1\aeset.dat", string:path);
    exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\avscan.exe", string:path);
    NetUseDel(close:FALSE);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      exit(0);
    }

    # Determine the version of Avira.
    ver_app = NULL;
    ver_engine = NULL;

    fh = CreateFile(
      file:exe,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (isnull(fh)) break;

    ver_app = GetFileVersion(handle:fh);

    CloseFile(handle:fh);

    # Determine the Version of the Scan Engine
    fh = CreateFile(
      file:engine,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver_engine = GetFileVersion(handle:fh);
      CloseFile(handle:fh);
    }
    else
    {
      fh = CreateFile(
        file:engine_2,
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
          contents = strstr(contents, "<ENGINESET>");
          contents = contents - strstr(contents, "</ENGINESET>");
          foreach line(split(contents, keep:FALSE))
          {
            if ("VERSION" >< line && isnull(ver_engine))
            {
              ver_engine = ereg_replace(pattern:"^.+[\t]*=[\t]*([0-9\.]+)$", replace:"\1", string:line);
              ver_engine = split(ver_engine,sep:".",keep:FALSE);
            }
            if (!isnull(ver_engine)) break;
          }
        }
        CloseFile(handle:fh);
      }
    }

    # Check the version
    if((!isnull(ver_app))&&(!isnull(ver_engine)))
    {
      if (
        (
          ver_app[0] =~ "^[78]" && isnull(contents) &&
                         (((ver_engine[0] < 7) ||
                         (ver_engine[0] == 7 && ver_engine[1] < 9) ||
                         (ver_engine[0] == 7 && ver_engine[1] < 9  && ver_engine[2] == 0 && ver_engine[3] < 180)))
         ) ||
         (
           ver_app[0] =~ "^[89]" && !isnull(contents) &&
 	                ((ver_engine[0] < 8) ||
                         (ver_engine[0] == 8 && ver_engine[1] < 2) ||
                         (ver_engine[0] == 8 && ver_engine[1] == 2  && ver_engine[2] == 0 && ver_engine[3] < 180)))
       )
      {
        app_version = string(ver_app[0], ".", ver_app[1], ".", ver_app[2], ".", ver_app[3]);
        ver_engine = string(ver_engine[0],".",ver_engine[1],".",ver_engine[2],".",ver_engine[3]);

        #Set the info in the report

        report = report + string(
          "\n",
          "Product Name       : ", prod, "\n",
          "Version            : ", app_version, "\n",
          "Scan Engine        : ", ver_engine, "\n",
          "Installation Path  : ", path, "\n"
        );
        s++;
      }
    }
  }
}
NetUseDel();


if (s > 0)
{
  if (report_verbosity > 0)
  {
    if (s == 1)
      report = "Nessus found the following affected install of Avira AntiVir :" + report;
    else
      report = "Nessus found the following affected installs of Avira AntiVir :"+ report;
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
