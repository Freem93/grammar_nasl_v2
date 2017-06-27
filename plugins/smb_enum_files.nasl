#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(23973);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2015/01/12 17:12:47 $");

 script_name(english:"SMB Share Files Enumeration");
 script_summary(english:"Gets the list of files on remote shares");

 script_set_attribute(attribute:"synopsis", value:"This plugin enumerates files on remote shares.");
 script_set_attribute(attribute:"description", value:
"By connecting to the remote host with the supplied credentials, this
plugin enumerates files listed on the remote share and stores the list
in the knowledge base so that it can be used by other plugins.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/04");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_accessible_shares.nasl");
 if ( NASL_LEVEL >= 3000 ) script_dependencies("wmi_enum_files.nbin");
 script_exclude_keys("SMB/WMI/FilesEnumerated");
 script_require_keys("SMB/shares");
 script_require_ports(139, 445);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

if (get_kb_item("SMB/WMI/FilesEnumerated")) exit(0, "SMB shares have already been enumerated via WMI.");

port = kb_smb_transport();


global_var MaxRecursivity, file_type_list, login, pass;

ext_regex = "\.([^.]+)$";                                   # used to extract file extension.
file_count = 0;                                             # track # files matching an extension of interest
max_files_total = 4096;                                     # max files with an extension of interest

# nb: '10' is arbitrary here; we just need a way to prevent an endless
#     loop if we scan a rogue server or stumble on a symlink loop.
if ( thorough_tests ) MaxRecursivity = 10;
else MaxRecursivity = 3;

# nb: the list of extensions here should match what's in wmi_enum_files.nbin
if (thorough_tests)
 file_type_list = make_list(
                        "mp3","ogg","flac","au","mid","aif","aiff","aifc","aac","ra","m4a","wma",	# Audio
                        "mpg","mpeg","avi","divx","vob","mp4","mkv","3gp","asf","mov","rm","wmv","flv",	# Video
                        "doc","docx","docm","dotx","dotm","dot",					# MS Word
                        "ppt","pptx","pptm","potx","potm","pot","ppsx","ppsm","pps","ppam","ppa",       # MS PowerPoint
                        "xls","xlsx","xlsm","xlsb","xltx","xltm","xlt","xlam","xla","xps",		# MS Excel
                        "mdb","mde",									# MS Access
			"dbx","pst","mbx",								# MS Outlook
			"ical","ics","ifb",								# iCalendar
                        "rtf","txt","wri","wps","pub","pdf",						# Other editors
                        "csv","dif",									# Other spreadsheets
                        "odc","ods","odt","odp",							# OpenDocument
                        "sxw","sxi","sxc",								# OO
			"sdw","sdd","sdc",								# Star*
			"torrent");									# Torrent
else
 file_type_list = make_list("mp3", "wmv", "mpg", "avi", "wma", "divx", "xls", "doc", "ppt", "torrent");


# nb: the list of windows files here should match what's in wmi_enum_files.nbin
windows_files = make_list(
  # in \windows
  "clock.avi",
  # in \documents and settings\all users\documents\my music\sample music
  "new stories (highway blues).wma",
  "beethoven's symphony no. 9 (scherzo).wma",
  # in \users\public\music\sample music
  "kalimba.mp3",
  "maid with the flaxen hair.mp3",
  "sleep away.mp3",
  # in \program files\common files\microsoft shared\ink
  "flickanimation.avi",
  # in \program files\common files\microsoft shared\ink\en-us\
  "split.avi",
  "join.avi",
  "delete.avi",
  "boxed-correct.avi",
  "boxed-delete.avi",
  "boxed-join.avi",
  "boxed-split.avi",
  "correct.avi",
  # in \programdata\microsoft\windows\ringtones
  "ringtone 01.wma",
  "ringtone 02.wma",
  "ringtone 03.wma",
  "ringtone 04.wma",
  "ringtone 05.wma",
  "ringtone 06.wma",
  "ringtone 07.wma",
  "ringtone 08.wma",
  "ringtone 09.wma",
  "ringtone 10.wma"
);

# ext_array is used to easily determine if an extension is to be tracked.
ext_array = make_array();
foreach ext (file_type_list)
  ext_array[ext]++;

function list_dir(basedir, level)
{
  local_var ext, files_of_interest, match, name, ret, subsub;

  # nb: limit how deep we'll recurse.
  if (level > MaxRecursivity) return NULL;

  files_of_interest = make_list();

  ret = FindFirstFile(pattern:basedir + "\*");
  while (!isnull(ret[1]))
  {
    name = ret[1];
    if (name != '.' && name != '..')
    {
      if (ret[2] & FILE_ATTRIBUTE_DIRECTORY)
      {
        subsub = list_dir(basedir:basedir+"\"+name, level:level+1);
        if (!isnull(subsub)) files_of_interest = make_list(files_of_interest, subsub);
      }
      else
      {
        match = eregmatch(pattern:ext_regex, string:name);
        if (!isnull(match))
        {
          ext =  tolower(match[1]);
          if (ext_array[ext] > 0) files_of_interest = make_list(files_of_interest, basedir+"\"+name);
        }
      }
    }
    ret = FindNextFile(handle:ret);
  }

  return files_of_interest;
}

function find_files(share)
{
  local_var dir, dirs, ext, r, suspect;

  r = NetUseAdd(login:login, password:pass, share:share);
  if (r != 1) return NULL;

  suspect = NULL;

  dirs = list_dir(basedir:NULL, level:0);
  if (!isnull(dirs))
  {
    foreach dir (dirs)
    {
      if (ereg(pattern:"^MVI_", string:dir, icase:TRUE)) continue;

      if (isnull(suspect)) suspect = make_list(dir);
      else suspect = make_list(suspect, dir);

      file_count++;
      if (file_count > max_files_total) break;
    }
  }

  NetUseDel(close:FALSE);
  return(suspect);
}

#
# Here we go
#

login = kb_smb_login();
pass =  kb_smb_password();
dom = kb_smb_domain();

shares = get_kb_list_or_exit("SMB/shares");

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

foreach share (make_list(shares))
{
  if ( share != "ADMIN$" && share != "IPC$" )
  {
    files = find_files(share:share);
    if (!isnull(files))
    {
      foreach file (files)
      {
        if ("." >!< file) continue;

        # nb: ignored since they're included in Windows.
        if (report_paranoia < 2)
        {
          lfile = tolower(file);
          ignored = FALSE;
          foreach windows_file (windows_files)
          {
            if (windows_file >< lfile)
            {
              ignored = TRUE;
              break;
            }
          }
          if (ignored) continue;
        }

        match = eregmatch(pattern:ext_regex, string:file);
        if (!isnull(match))
        {
          ext =  tolower(match[1]);
          if (ext_array[ext] > 0)
          {
            set_kb_item(name:"SMB/"+share+"/content/extensions/"+ext, value:file);
            # display("SMB/" + share + "/content/extensions/" + ext, " => ",  file, "\n");
          }
        }
      }
    }
  }
}
NetUseDel();
