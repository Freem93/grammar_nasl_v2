#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40820);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_name(english:"Cerberus FTP Server Detection");
  script_summary(english:"Checks if Cerberus FTP is installed.");

  script_set_attribute(attribute:"synopsis", value:"An FTP server is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:"Cerberus FTP server is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.cerberusftp.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cerberusftp:ftp_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_func.inc");
include("misc_func.inc");
include("smb_reg_query.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

win_prog_paths = make_list();

path_86 = hotfix_get_programfilesdir();
if (!isnull(path_86)) win_prog_paths = make_list(path_86);

arch = get_kb_item_or_exit('SMB/ARCH');
if (arch == "x64")
{
  path_64 = hotfix_get_programfilesdirx86();
  if (!isnull(path_64)) win_prog_paths = make_list(win_prog_paths, path_64);
}

potentials = make_array(
  "CerberusGUI.exe", "\Cerberus LLC\Cerberus FTP Server",
  "Cerberus.exe", "\Cerberus"
);

info = NULL;
current_share = NULL;
open_share = NULL;
errors = make_list();

foreach win_prog_path (win_prog_paths)
{
  current_share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:win_prog_path);

  if (isnull(open_share) || current_share != open_share)
  {
    if (!isnull(open_share)) NetUseDel(close:FALSE);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:current_share);
    if (rc != 1)
    {
      errors = make_list(errors, "Failed to access '"+current_share+".");
      NetUseDel(close:FALSE);
      open_share = NULL;
      continue;
    }
    else open_share = current_share;
  }

  foreach potential (keys(potentials))
  {
    path = win_prog_path + potentials[potential];
    file = path + "\" + potential;
    file2 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);

    fh = CreateFile(
      file:file2,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );

    if (!isnull(fh))
    {
      version = GetProductVersion(handle:fh);
      if (!isnull(version) && strlen(version) > 0)
      {
        # Older versions return version like "#, #, #"
        if (", " >< version)
          version = str_replace(string:version, find:", ", replace:".");

        set_kb_item(name:"SMB/CerberusFTP/" + path + "/file", value:potential);
        set_kb_item(name:"SMB/CerberusFTP/" + path + "/version", value:version);

        info +=
            '\n' +
            '\n  Path         : ' + path    +
            '\n  Version      : ' + version;
      }
      else errors = make_list(errors, "Failed to get version of "+file+".");
      CloseFile(handle:fh);
    }
  }
}
NetUseDel();

# Grab interface configuration if possible
winroot = hotfix_get_systemroot();
share = ereg_replace(pattern:'^([A-Za-z]:).*', replace:"\1\", string:winroot);
interface_files = make_list(
  "ProgramData\Cerberus LLC\Cerberus FTP Server\interfaces.xml",
  "ProgramData\Cerberus LLC\Cerberus FTP Server\listeners_2.0.xml",
  "Documents and Settings\All Users\Application Data\Cerberus LLC\Cerberus FTP Server\interfaces.xml",
  "Documents and Settings\All Users\Application Data\Cerberus LLC\Cerberus FTP Server\listeners_2.0.xml"
);
registry_init();

foreach interface_file (interface_files)
{
   if ("_2.0" >< interface_file) sep = "</listener>";
   else sep = "</interface>";

   contents = hotfix_get_file_contents(share + interface_file);

   # Skip on error
   if (contents["error"] != HCF_OK) continue;

   interface_chunks = split(contents['data'], sep:sep, keep:TRUE);
   foreach interface_chunk (interface_chunks)
   {
     if (
       "<active>1</active>" >!< interface_chunk
       &&
       "<isActive>true</isActive>" >!< interface_chunk
     ) continue;

     if (interface_chunk =~ '<(interface|listener) (name="[^"]+" type="1">|type="FTP")')
       set_kb_item(name:"SMB/CerberusFTP/active_ftp", value:TRUE);
     if (interface_chunk =~ '<(interface|listener) (name="[^"]+" type="2">|type="FTPS")')
       set_kb_item(name:"SMB/CerberusFTP/active_ftps", value:TRUE);
     if (interface_chunk =~ '<(interface|listener) (name="[^"]+" type="4">|type="SSH FTP"|type="SSH SFTP")')
       set_kb_item(name:"SMB/CerberusFTP/active_sshftp", value:TRUE);
     if (interface_chunk =~ '<(interface|listener) (name="[^"]+" type="8">|type="HTTP")')
       set_kb_item(name:"SMB/CerberusFTP/active_http", value:TRUE);
     if (interface_chunk =~ '<(interface|listener) (name="[^"]+" type="16">|type="HTTPS")')
       set_kb_item(name:"SMB/CerberusFTP/active_https", value:TRUE);
   }
}
# Close handles.
hotfix_check_fversion_end();

if (!isnull(info))
{
  set_kb_item(name:"SMB/CerberusFTP/Installed", value:TRUE);


  register_install(
    app_name:"Cerberus FTP",
    path:path,
    version:version,
    cpe:"cpe:/a:cerberusftp:ftp_server");

  if (report_verbosity > 0)
  {
    report = info;

    # Add errors if present
    if (max_index(errors))
    {
      report +=
        '\n\n' +
        '  Note that the results may be incomplete because of the following ';

      if (max_index(errors) == 1) report += 'error\n  that was';
      else report += 'errors\n  that were';

      report +=
        ' encountered :\n' +
        '\n' +
        '  ' + join(errors, sep:'\n  ') + '\n';
    }
    security_note(port:port, extra:report);
  }
  else security_note(port);

  if (max_index(errors)) exit(1, "The results may be incomplete because of one or more errors verifying installs.");
  else exit(0);
}

if (max_index(errors))
{
  if (max_index(errors) == 1) errmsg = errors[0];
  else errmsg = 'Errors were encountered verifying installs : \n  ' + join(errors, sep:'\n  ');

  exit(1, errmsg);
}
else audit(AUDIT_NOT_INST, "Cerberus FTP");
