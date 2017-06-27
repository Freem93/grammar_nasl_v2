#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36141);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_cve_id("CVE-2007-4514");
  script_bugtraq_id(34451);
  script_osvdb_id(53596);

  script_name(english:"HP ProCurve Manager Remote Unauthorized Access to Data (HPSBMA02420 SSRT071458)");
  script_summary(english:"Checks which patches have been applied");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP ProCurve Manager (PCM) installed on the remote host
reportedly contains a vulnerability that could allow remote attackers
the ability to access arbitrary files hosted on the PCM server.");
  # http://cdn.procurve.com/training/Manuals/PCM23_u10-Release-Notes-0309.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3a81293");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/502585/30/0/threaded"
  );
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as referenced in the vendor advisory
above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(200);

 script_set_attribute(attribute:"patch_publication_date", value:"2009/04/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:procurve_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Make sure the affected service is running, unless we're being paranoid.
if (report_paranoia < 2)
{
  services = get_kb_item("SMB/svcs");
  if (
    services &&
    "ProCurve Network Manager" >!< services
  ) exit(0);
}


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Find the installation path.
path = NULL;

key = "SOFTWARE\HP\ProCurve Manager";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Grab the version / update id.
version = NULL;
update_id = NULL;

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
prp =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\server\config\update_history.prp", string:path);
cfg =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\server\config\TyphoonServer.cfg", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:prp,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (!isnull(fh))
{
  # no more than 10K.
  chunk = 10240;
  fsize = GetFileSize(handle:fh);
  if (fsize > 0)
  {
    if (chunk > fsize) chunk = fsize;
    data = ReadFile(handle:fh, length:chunk, offset:0);

    if (strlen(data))
    {
      foreach line (split(data, keep:FALSE))
      {
        if (line =~ "^ *PCM_B_[0-9]+_[0-9]+[^ {]*")
        {
          version = ereg_replace(pattern:"^ *PCM_(B_[0-9]+_[0-9]+[^ {]*).*", replace:"\1", string:line);
          version = str_replace(find:"_", replace:".", string:version);
        }
        else if (line =~ "^ *B_[0-9]+_[0-9]+[^ {]*")
          update_id = ereg_replace(pattern:"^ *(B_[0-9]+_[0-9]+[^ {]*).*", replace:"\1", string:line);

        if (version && update_id) break;
      }
    }
  }
  CloseFile(handle:fh);
}

if (isnull(version))
{
  fh = CreateFile(
    file:cfg,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (!isnull(fh))
  {
    # no more than 10K.
    chunk = 10240;
    fsize = GetFileSize(handle:fh);
    if (fsize > 0)
    {
      if (chunk > fsize) chunk = fsize;
      data = ReadFile(handle:fh, length:chunk, offset:0);

      if (strlen(data))
      {
        foreach line (split(data, keep:FALSE))
        {
          if (line =~ "^ *PRODUCT_REVISION *= *(B\.[0-9]+\.[0-9]+[^ {]*)")
          {
            version = ereg_replace(pattern:"^ *PRODUCT_REVISION *= *(B\.[0-9]+\.[0-9]+[^ {]*).*", replace:"\1", string:line);
            version = str_replace(find:"_", replace:".", string:version);
            break;
          }
        }
      }
    }
    CloseFile(handle:fh);
  }
}
NetUseDel();


# Check the version number / update id.
if (!isnull(version))
{
  v = split(version, sep:'.', keep:FALSE);

  if (
    v[0] == 'B' &&
    (
      int(v[1]) < 2 ||
      (
        int(v[1]) == 2 &&
        (
          int(v[2]) < 320 ||
          (int(v[2]) == 321 && (isnull(update_id) || update_id =~ "^B_02_30_[0-9]$")) ||
          (int(v[2]) == 322 && (isnull(update_id) || update_id =~ "^B_02_30_[0-9]$"))
        )
      )
    )
  )
  {
    if (report_verbosity > 0)
    {
      if (isnull(update_id)) update_id = "n/a";

      report = string(
        "\n",
        "Nessus collected the following information about the remote install of\n",
        "ProCurve Manager :\n",
        "\n",
        "  PCM Version : ", version, "\n",
        "  Update ID   : ", update_id, "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
