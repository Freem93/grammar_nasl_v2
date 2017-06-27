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
# - Revised plugin title, output formatting (8/22/09)
# - changed family (9/4/09)

include("compat.inc");

if(description)
{
	script_id(17342);
	script_version ("$Revision: 1.11 $");
	script_cvs_date("$Date: 2012/09/24 21:53:41 $");

	script_name(english:"Cisco IOS TFTP File Disclosure");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote TFTP daemon is serving potentially sensitive content."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a TFTP server installed that is serving one or
more Cisco IOS files.  These files may contain passwords and other
sensitive information.  A remote attacker could use this information
to mount further attacks."
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

	script_summary(english:"Determines if the remote host has sensitive files exposed via TFTP (Cisco IOS)");
	script_category(ACT_ATTACK);
	script_copyright(english:"This NASL script is Copyright (C) 2005-2012 Corsaire Limited.");
	script_family(english:"Misc.");
	script_dependencies('tftpd_detect.nasl', 'tftpd_backdoor.nasl');
	script_require_keys("Services/udp/tftp");
	script_exclude_keys('tftp/backdoor');	# Not wise but quicker
 	exit(0);
}



############## declarations ################





############## script ################

include("tftp.inc");
include("misc_func.inc");

port = get_kb_item('Services/udp/tftp');
if (! port)
 if (COMMAND_LINE)
  port = 69;
 else
  exit(0);

# Avoid FP
if (get_kb_item('tftp/'+port+'/backdoor')) exit(0);

# initialise variables
local_var request_data;
local_var detected_files;
local_var file_name;
local_var file_list;
file_list=make_list('startup-config','network-confg','network.cfg','network.confg','cisconet-confg','cisconet.cfg','cisconet.confg','router-confg','router.config','router.cfg','ciscortr-confg','ciscortr.config','ciscortr.cfg','cisco-confg','cisco.confg','cisco.cfg');

if ( tftp_get(port:port,path:rand_str(length:10)) ) exit(0); 


# step through files
foreach file_name (file_list)
{
	# request file
	if(request_data=tftp_get(port:port,path:file_name))
	{
		tftp_ms_backdoor(data: request_data, file: file_name, port: port);
		if (substr(request_data, 0, 1) == 'MZ' && 
    'This program cannot be run in DOS mode' >< request_data)
			exit(0);
		# add filename to response
		detected_files=raw_string(detected_files,file_name,"\n");
	}
}


# check if any files were detected
if(detected_files)
{
 report = "
Nessus discovered the following files :

" + detected_files + "
";
 security_warning(extra:report,port:port,proto:"udp");
}

exit(0);
