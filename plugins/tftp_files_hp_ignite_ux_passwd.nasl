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
# - Revised plugin title, OSVDB ref, output formatting, family change (8/22/09)

include("compat.inc");

if(description)
{
	script_id(19509);
	script_version ("$Revision: 1.12 $");
	script_cve_id("CVE-2004-0951");
	script_bugtraq_id(14568);
        script_osvdb_id(18749);

	script_name(english:"HP Ignite-UX TFTP /etc/pass File Disclosure");
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote TFTP daemon has an information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a vulnerable version of the HP Ignite-UX
application installed that exposes the /etc/passwd file to anonymous
TFTP access.  A remote attacker could use this information to mount
further attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://research.corsaire.com/advisories/c041123-001.txt"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Apply the appropriate vendor patch."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/16");
 script_cvs_date("$Date: 2011/03/16 13:37:58 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

	script_summary(english:"Determines if the remote host has sensitive files exposed via TFTP (HP Ignite-UX passwd)");
	script_category(ACT_ATTACK);
	script_copyright(english:"This NASL script is Copyright (C) 2005-2011 Corsaire Limited.");
	script_family(english:"Misc.");
	script_dependencies("tftpd_backdoor.nasl");
	script_require_keys("Services/udp/tftp");
	script_exclude_keys('tftp/backdoor'); # Not wise but quicker
 	exit(0);
}



############## declarations ################

port = get_kb_item('Services/udp/tftp');
if ( ! port ) exit(0);
if ( get_kb_item("tftp/" + port + "/backdoor") ) exit(0);






############## script ################

include("tftp.inc");
include("dump.inc");

# initialise test
file_name='/var/opt/ignite/recovery/passwd.makrec';
data = tftp_get(port:port,path:file_name);
tftp_ms_backdoor(port: port, data: data, file: file_name);
if (data)
 security_warning(port:port,proto:"udp", 
               extra: '\nFile content :\n'+hexdump(ddata: data)+'\n');
