#
# This NASL script was written by Martin O'Neal of Corsaire (http://www.corsaire.com)
# 
# The script will test whether the remote host has one of a number of sensitive  
# files present on the tftp server
#
# DISCLAIMER
# The information contained within this script is supplied "as-is" with 
# no warranties or guarantees of fitness of use or otherwise. Corsaire 
# accepts no responsibility for any damage caused by the use or misuse of 
# this information.
#
# GPLv2
# 

# Changes by Tenable:
# - Revised plugin title, output formatting, family change (8/22/09)


include("compat.inc");

if(description)
{
	script_id(17341);
	script_version ("$Revision: 1.8 $");
	script_cvs_date("$Date: 2012/09/26 21:37:15 $");

	script_name(english:"Cisco IOS Device TFTP Certificate Authority (CA) File Detection");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote TFTP daemon is serving potentially sensitive content."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a TFTP server installed that is serving one or
more Cisco IOS Certificate Authority (CA) files.  These
files may include the private key for the CA, which is
information that should be considered sensitive."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Disable the TFTP service if it is not being used.  Otherwise,
restrict access to trusted sources only."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/16");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

	script_summary(english:"Determines if the remote host has sensitive files exposed via TFTP (Cisco IOS CA)");
	script_category(ACT_ATTACK);
	script_copyright(english:"This NASL script is Copyright (C) 2005-2012 Corsaire Limited.");
	script_family(english:"Misc.");
	script_dependencies("tftpd_detect.nasl", "tftpd_backdoor.nasl");
	script_require_keys("Services/udp/tftp");
	script_exclude_keys('tftp/backdoor'); # Not wise but quicker
 	exit(0);
}

############## script ################

include("tftp.inc");

# initialise variables
local_var request_data;
local_var file_name;
local_var file_postfix;
local_var postfix_list;
local_var ca_name;
local_var detected_files;
local_var description;
postfix_list=make_list('.pub','.crl','.prv','.ser','#6101CA.cer','.p12');

port = get_kb_item('Services/udp/tftp');
if (! port)
 if (COMMAND_LINE)
  port = 69;
 else
  exit(0);

if (get_kb_item('tftp/'+port+'/backdoor')) exit(0);	# Quicker

# step through first nine certificate files
for(i=1;i<10;i++)
{
	# initialise variables
	file_name=raw_string(ord(i),'.cnm');
	
	# request numeric certificate file
	if(request_data=tftp_get(port:port,path:file_name))
	{
		tftp_ms_backdoor(data: request_data, file: file_name, port: port);
		# initialise variables
		ca_name=eregmatch(string:request_data,pattern:'subjectname_str = cn=(.+),ou=');
		
		# check if cn is present in certificate file
		if(ca_name[1])
		{
			# add filename to response
			detected_files=raw_string(detected_files,file_name,"\n");
			
			# step through files
			foreach file_postfix (postfix_list)
			{
				# initialise variables
				file_name=raw_string(ca_name[1],file_postfix);

				# request certificate file
				if(request_data=tftp_get(port:port,path:file_name))
				{
					tftp_ms_backdoor(data: request_data, file: file_name, port: port);
					# add filename to response
					detected_files=raw_string(detected_files,file_name,"\n");
				}
			}
			
			break;
		}
	}
}

# check if any files were detected
if(detected_files)
{
  report = "
Nessus detected some potentially sensitive files :

" + detected_files + "
";
  security_warning(extra:report,port:port,proto:"udp");
}


exit(0);
