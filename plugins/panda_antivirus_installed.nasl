#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20283);
  script_version("$Revision: 1.1715 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_name(english:"Panda Antivirus Detection and Status");
  script_summary(english:"Checks for Panda Antivirus.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"Panda Antivirus, a commercial antivirus software package for Windows,
is installed on the remote host. However, there is a problem with the
installation; either its services are not running or its engine and/or
virus definitions are out of date.");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"see_also", value:"http://www.pandasecurity.com/");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pandasecurity:panda_antivirus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport", "SMB/Services/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("antivirus.inc");
include("byte_func.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("datetime.inc");

# Connect to the remote registry.
get_kb_item_or_exit("SMB/registry_full_access");
get_kb_item_or_exit("SMB/Services/Enumerated");

login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

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
# - for Panda Titanium / TruProtect.
prod++;
prod_subkeys[prod] = "Panda Antivirus Lite";
name_subkeys[prod] = "PRODUCT";
path_subkeys[prod] = "DIR";
ver_subkeys[prod]  = "VERSION";
# - for Platinum / Antivirus Pro 2009
prod++;
prod_subkeys[prod] = "Setup";
name_subkeys[prod] = "PRODUCTNAME";
path_subkeys[prod] = "PATH";
ver_subkeys[prod]  = "NORMAL";

foreach prod (keys(prod_subkeys)) {
  key = string("SOFTWARE\\Panda Software\\", prod_subkeys[prod]);
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    name = NULL;
    if (prod_subkeys[prod] == "Setup")
    {
      value = RegQueryValue(handle:key_h, item:"LPRODUCTNAME");
      if (!isnull(value)) name = value[1];
    }
    if (isnull(name))
    {
      value = RegQueryValue(handle:key_h, item:name_subkeys[prod]);
      if (!isnull(value)) name = value[1];
    }

    value = RegQueryValue(handle:key_h, item:path_subkeys[prod]);
    if (!isnull(value)) {
      path = ereg_replace(string:value[1], pattern:"\$", replace:"");
    }

    value = RegQueryValue(handle:key_h, item:ver_subkeys[prod]);
    if (!isnull(value)) {
      ver = value[1];
    }

    RegCloseKey (handle:key_h);

    # We found a product so we're done.
    break;
  }
  else name = NULL;
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (isnull(name) || isnull(path) || isnull(ver))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, "Panda Antivirus");
}
set_kb_item(name:"Antivirus/Panda/installed", value:TRUE);
set_kb_item(name:"Antivirus/Panda/" + name, value:ver + " in " + path);

# Get info about the virus signatures.
sigs_target = "unknown";
if (!isnull(path))
{
  # Read signature date from the file PAV.SIG.
  #
  # nb: it's also encoded as year-day-month in the file in
  #     bytes 0x65-0x68; eg, d5 07 11 0a => 2005-Oct-17
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  sigfile =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\pav.sig", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1) {
    fh = CreateFile(
      file:sigfile,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh)) {
      hex_date = ReadFile(handle:fh, offset:0x65, length:4);

      if (!isnull(hex_date)) {
        set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
        year  = getword(blob:hex_date, pos:0);
        day   = getbyte(blob:hex_date, pos:2);
        if (len(day) == 1) day = string("0", day);
        month = getbyte(blob:hex_date, pos:3);
        if (len(month) == 1) month = string("0", month);
        sigs_target = string(month, "-", day, "-", year);
        set_kb_item(name:"Antivirus/Panda/sigs", value:sigs_target);

      }

      CloseFile(handle:fh);
    }

    if(sigs_target == "unknown")
    {
      dirpath = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1", string:path);

      timestamp = 0;
      file = FindFirstFile(pattern:dirpath + "\cache\*.sig");

      while (!isnull(file[1]))
      {
        # Get the Epoch time of the date created,
        # we want the time for the most recent pattern file.
        if (!isnull(file[3][1]) && timestamp < file[3][1])
        {
          timestamp = file[3][1]; # 1 should be the date modified.
          file_name = file[1]; # Let's track the file name.
        }
        file = FindNextFile(handle:file);
      }

      # Let's convert the timestamp to a format the plugin expects
      if (timestamp == 0) file_date = 0;
      else file_date = strftime('%m-%d-%Y', timestamp);

      if (!isnull(file_name))
        set_kb_item(name:"Antivirus/Panda/panda_sig_file", value:file_name);
      if (!isnull(file_date))
      {
        sigs_target = file_date;
        replace_kb_item(name:"Antivirus/Panda/sigs", value:sigs_target);
      }
    }

    NetUseDel(close:FALSE);
  }
}
NetUseDel();

# Generate report
trouble = 0;

# - general info.
report = "Panda Antivirus is installed on the remote host :

  Product Name:      " + name + "
  Version:           " + ver + "
  Installation Path: " + path + "
  Virus signatures:  " + sigs_target + "

";

# - sigs out-of-date?
info = get_av_info("panda");
if (isnull(info)) exit(1, "Failed to get Panda Antivirus info from antivirus.inc.");
sigs_vendor_yyyymmdd = info["sigs_vendor_yyyymmdd"];

if (sigs_target =~ "^[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]") {
  a = split(sigs_target, sep:"-", keep:0);
  sigs_target_yyyymmdd = string(a[2], a[0], a[1]);

  if (int(sigs_target_yyyymmdd) < ( int(sigs_vendor_yyyymmdd) - 1 )) {
    sigs_vendor_mmddyyyy = string(
      substr(sigs_vendor_yyyymmdd, 4, 5),
      "-",
      substr(sigs_vendor_yyyymmdd, 6, 7),
      "-",
      substr(sigs_vendor_yyyymmdd, 0, 3)
    );

    report += "The virus signatures on the remote host are out-of-date - the last
known update from the vendor is " + sigs_vendor_mmddyyyy + "

";
    trouble++;
  }
}


# - services running.
services = get_kb_item("SMB/svcs");

if (services)
{
  running = FALSE;

  services = tolower(services);
  if (
    # Panda Antivirus Service
    (
      # - english
      "panda anti-virus service" >< services ||
      "panda on-access anti-malware service" >< services ||
      # - german
      "panda antivirus service" >< services ||
      "[ pavsrv ]" >< services ||
      # Panda Antivirus Service for 2015
      "panda antivirus pro" >< services ||
      # Panda Endpoint Protection
      "panda product service" >< services
    ) &&
    # Panda Process Protection Service
    # or Panda Endpoint Local Process Manager
    (
      "panda process protection service" >< services ||
      "[ pavprsrv ]" >< services ||
      "panda endpoint local process manager" >< services ||
      "[ pavwaslpmng ]" >< services ||
      "panda software controller" >< services ||
      # Panda Local Agent for 2015
      "[ pandaagent ]" >< services ||
      # Panda Endpoint Protection
      "panda endpoint administration agent"
    )
  ) running = TRUE;

  if (!running)
  {
    report += 'The remote Panda Antivirus service is not running.\n\n';
    trouble++;
  }
}
else
{
  report += 'We were unable to retrieve a list of running services from the host.\n\n';
  trouble++;
}

if (trouble) report += "As a result, the remote host might be infected by viruses.";

if (trouble) {
  security_hole(port:port, extra:'\n'+report);
}
else {
  # nb: antivirus.nasl uses this in its own report.
  set_kb_item (name:"Antivirus/Panda/description", value:report);
  exit(0, "Detected Panda Antivirus with no known issues to report.");
}
