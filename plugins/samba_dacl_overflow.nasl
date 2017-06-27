#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15985);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2004-1154");
 script_bugtraq_id(11973);
 script_osvdb_id(12422);

 script_name(english: "Samba smbd Security Descriptor Parsing Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Remote code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote Samba server, according to its version number, is vulnerable to 
a remote buffer overrun resulting from an integer overflow vulnerability.

To exploit this flaw, an attacker would need to send to the remote host
a malformed packet containing hundreds of thousands of ACLs, which would
in turn cause an integer overflow resulting in a small pointer being allocated.

An attacker needs a valid account or enough credentials to exploit this
flaw." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 3.0.10 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/16");
 script_cvs_date("$Date: 2011/04/13 18:22:59 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/02/11");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
 script_end_attributes();

 script_summary(english: "checks samba version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english: "Gain a shell remotely");
 script_dependencie("smb_nativelanman.nasl");
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

if ( get_kb_item("CVE-2004-1154") ) exit(0);

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba ([0-2]\.|3\.0\.[0-9]$)", string:lanman))security_hole(139);
}
