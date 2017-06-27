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

# Changes by Tenable:
# - Revised plugin title, output formatting, family change (8/22/09)

include("compat.inc");

if(description)
{
	script_id(19508);
	script_version ("$Revision: 1.9 $");
	script_cvs_date("$Date: 2012/09/24 21:48:39 $");

	script_name(english:"HP Ignite-UX TFTP File Access Information Disclosure");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote TFTP daemon is serving potentially sensitive content."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a TFTP server installed that is serving one or
more HP Ignite-UX files.  These files may contain sensitive
information.  A remote attacker could use this information to mount
further attacks."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Disable the TFTP service if it is not being used.  Otherwise,
restrict access to trusted sources only."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/26");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

	script_summary(english:"Determines if the remote host has sensitive files exposed via TFTP (HP Ignite-UX)");
	script_category(ACT_ATTACK);
	script_copyright(english:"This NASL script is Copyright (C) 2005-2012 Corsaire Limited.");
	script_family(english:"Misc.");
	script_dependencies("tftpd_backdoor.nasl");
	script_require_keys("Services/udp/tftp");
	script_exclude_keys('tftp/backdoor');	# Not wise but quicker
 	exit(0);
}



############## declarations ################

port = get_kb_item('Services/udp/tftp');
if ( ! port ) exit(0);
if ( get_kb_item("tftp/" + port + "/backdoor") ) exit(0);

############## script ################

include("tftp.inc");

# initialise variables

file_list=make_list('/var/opt/ignite/config.local','/var/opt/ignite/local/config','/var/opt/ignite/local/host.info','/var/opt/ignite/local/hw.info','/var/opt/ignite/local/install.log','/var/opt/ignite/local/manifest/manifest','/var/opt/ignite/recovery/makrec.append','/var/opt/ignite/server/ignite.defs','/var/opt/ignite/server/preferences');

# step through files
foreach file_name (file_list)
{
	# request file
	get = tftp_get(port:port,path:file_name);
	if(get)
	{
		tftp_ms_backdoor(data: get, port: port, file: file_name);
		security_warning(port:port,proto:"udp");
		exit(0);
	}
}

