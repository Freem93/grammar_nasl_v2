#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(23974);
 script_version ("$Revision: 1.13 $");
 
 script_name(english:"Microsoft Windows SMB Share Hosting Office Files");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote share contains Office-related files." );
 script_set_attribute(attribute:"description", value:
"This plugin connects to the remotely accessible SMB shares and
attempts to find office related files (such as .doc, .ppt, .xls, .pdf
etc)." );
 script_set_attribute(attribute:"solution", value:
"Make sure that the files containing confidential information have
proper access controls set on them." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/04");
 script_cvs_date("$Date: 2011/03/21 16:17:43 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_summary(english:"Lists .doc, .ppt, .xls and other office related files");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_accessible_shares.nasl","smb_enum_files.nasl");
 script_require_keys("SMB/shares");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include('global_settings.inc');

# Here we go
#		

monitored_file_ext_type = make_list ("doc","rtf","pub","wri","ppt","xls","csv","pdf","mdb","mde",	  # removed txt, FP prone
                                     "dif","sxw","sxi","sxc","sdw","sdd","sdc",
                                     "ods","odt","odp","odc",			   			  # OpenDocument formats
				     "xlsx","xlsm","xlsb","xltx","xltm","xlt","xlam","xla","xps", 	  # Office 2007 Excel formats
                                     "docx","docm","dotx","dotm","dot", 				  # Office 2007 Word formats
				     "pptx","pptm","potx","potm","pot","ppsx","ppsm","pps","ppam","ppa"); # Office 2007 PowerPoint formats

name = kb_smb_name();
login = kb_smb_login();
pass =  kb_smb_password();
dom = kb_smb_domain();

report = NULL;

shares = get_kb_list("SMB/shares");
if(!isnull(shares))  shares = make_list(shares);

count = 0;

foreach share (shares)
{
  file_list = NULL;
  if ( share != "ADMIN$" )
  {
    foreach ext (monitored_file_ext_type)
    {	
    if (isnull(file_list)) {
		 k  = get_kb_list("SMB/"+share+"/content/extensions/"+ext);
		 if ( ! isnull(k) )
		 	file_list = make_list(k);
		}
    else 	{
		 k  = get_kb_list("SMB/"+share+"/content/extensions/"+ext);
		 if ( ! isnull(k) )
		  	file_list = make_list(file_list, k);
		}
    }
    if (max_index(file_list) > 0)
    {		 
      report += "  + " + share + ' :\n\n';
	foreach file (file_list)
	{
  	 report += '    - ' + file + '\n';
	 count ++;
         if ( count > 255 ) break;
	}
      report += '\n';
    } 
  }
  if ( count > 255 ) break;
} 

if(!isnull(report))
 {
    report = "
Here is a list of office files which have been found on the remote SMB
shares :

" + report;

  if (count > 255)
  {
    report += string(
      "\n",
      "Note that Nessus has limited the report to 255 files although there\n",
      "may be more."
    );
  }
  security_note(port:kb_smb_transport(), extra:report);
}

