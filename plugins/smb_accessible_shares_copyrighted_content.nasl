#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11777);
 script_version("$Revision: 1.41 $");
 script_cvs_date("$Date: 2012/11/29 02:19:56 $");

 script_name(english:"Microsoft Windows SMB Share Hosting Possibly Copyrighted Material");
 script_summary(english:"Finds .mp3, .avi and .wav files");

 script_set_attribute(attribute:"synopsis", value:
"The remote host may contain material (movies/audio) infringing
copyright.");
 script_set_attribute(attribute:"description", value:
"This plugin displays a list of media files (such as .mp3, .ogg, .mpg,
.avi) which have been found on the remote SMB shares. 

Some of these files may contain copyrighted materials, such as
commercial movies or music files, that are being shared without the
owner's permission. 

If any of these files actually contain copyrighted material, and if they
are freely swapped around, your organization might be held liable for
copyright infringement by associations such as the RIAA or the MPAA." );
 script_set_attribute(attribute:"solution", value:"Delete the files infringing copyright.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/26");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_accessible_shares.nasl","smb_hotfixes.nasl", "smb_enum_files.nasl","smb_enum_softwares.nasl");
 script_require_keys("SMB/shares");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

# Here we go
#		

monitored_file_ext_type = make_list("mp3","mpg","mpeg","wav","ogg","avi","wma","divx","xvid","mkv","mp4","asf","mka","vob","torrent");

# poular list of DVD copying software

software_list	= make_list (  "DVD Ripper",
                               "DVDRip",
			       "XviD MPEG4 Video Codec",
			       "DivX Converter",
			       "DivX Codec",
			       "DVD-CLONER",
			       "1Click DVD Copy",
			       "DVD Wizard PRO",
			       "Gordian Knot",
                               "DVD Shrink",
                               "Handbrake",
			       "CloneDVD"); 		

name = kb_smb_name();
login = kb_smb_login();
pass =  kb_smb_password();
dom = kb_smb_domain();

report = NULL;
shares = get_kb_list_or_exit("SMB/shares");
shares = make_list(shares);

systemroot = hotfix_get_systemroot();
if ( ! systemroot ) exit(0); 
systemroot_share = ereg_replace(pattern:"^([A-Za-z]):.*", string:systemroot, replace:"\1$");
systemroot_path = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:systemroot, replace:"\1");
systemroot_path = tolower(str_replace(string:systemroot_path, find:'\\', replace:'\\\\'));



softwares = get_kb_list ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(softwares)) softwares = make_list(softwares);
else softwares = make_list();
count = 0;
flag = 0;

# Get the list of files on each share

foreach share (shares)
{
  file_list = NULL;
  flag = 0;
  if ( share != "ADMIN$" )
  {
    foreach ext (monitored_file_ext_type)
    {	
    if (isnull(file_list)) {
		k = get_kb_list("SMB/"+share+"/content/extensions/"+ext);
		if ( !isnull(k) ) 
			file_list = make_list(k);
		}
    else {
		k = get_kb_list("SMB/"+share+"/content/extensions/"+ext);
		if ( !isnull(k) ) 
			file_list = make_list(file_list, k);
	} 
    }
    if (max_index(file_list) > 0)
    {		 
	foreach file (file_list)
	{
 	 if ( share == systemroot_share &&
	      tolower(file) =~ "^" + systemroot_path )  continue;	
             
	 if ( flag == 0 )
	 {
      	   report += " + " + share + ' :\n\n';
	   flag ++;
	 }
  	 report += file + '\n';
	 count ++;
   	 if ( count > 255 ) break;
	}
      if ( count != 0 ) report += '\n';
    } 
  }
  if ( count > 255 ) break;
} 

# Check if any DVD copying software's or codecs are installed

installed_software = NULL;
	
if(max_index(softwares) > 0)
{
  foreach software (softwares)
   {
     foreach ks (software_list)
	{
	  if (ks >< software)
	  {
	    installed_software += software + '\n'; 	
	  }
	}		   	
   }
}

if(report != NULL)
 {
  report = "
Here is a list of files which have been found on the remote SMB shares.
Some of these files may contain copyrighted materials, such as commercial
movies or music files."+ '\n\n'+

  report + '\n';

 if (!isnull(installed_software))
 { 
  report += "In addition to the files, the following software that can be used to copy copyrighted DVDs are installed : "+ 
 	     '\n\n' 
	     + installed_software + '\n' +
	     "If the use of these software applications is not in line with your corporate policy, you should un-install them."+' \n';
 }	

  security_note(port:kb_smb_transport(), extra:report);
 }

