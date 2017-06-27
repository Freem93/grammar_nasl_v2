#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12298);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2013/05/13 20:43:09 $");

 script_bugtraq_id(10514);
 script_osvdb_id(7915);

 script_name(english:"MS KB870669: ADODB.Stream object from Internet Explorer");
 script_summary(english:"Makes sure that a given registry key is missing");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a version of IE which may read and write to
local files.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a vulnerability in IE.  The ADODB.Stream
object can be used by a malicious web page to read and write to local
files. 

An attacker could use this flaw to gain access to the data on the remote
host.  To exploit this flaw, an attacker would need to set up a rogue
website and lure a user on the remote host into visiting it.  If the
website contains the proper call to the ADODB object, then it may
execute data on the remote host.");
 script_set_attribute(attribute:"solution", value:
"Microsoft produced a workaround for this problem :

http://support.microsoft.com/?kbid=870669");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:ie");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_ie_gt(7) != 0 ) exit(0);

value = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/ActiveX Compatibility/{00000566-0000-0010-8000-00AA006D2EA4}/Compatibility Flags");

if ( value && value != 1024  && hotfix_missing(name:"870669") )
   security_hole(0);
