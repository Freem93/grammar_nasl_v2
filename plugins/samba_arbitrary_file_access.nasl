#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15394);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2004-0815");
 script_bugtraq_id(11216, 11281);
 script_osvdb_id(10464, 10990);

 script_name(english:"Samba MS-DOS Path Request Arbitrary File Retrieval");

 script_set_attribute(attribute:"synopsis", value:
"The remote file server allows access to arbitrary files." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote Samba server is affected
by a flaw that allows an attacker to access arbitrary files which
exist outside of the shares's defined path.  An attacker needs a valid
account to exploit this flaw." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c682015" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Sep/458" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Oct/48" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 2.2.12 / 3.0.7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/30");
 script_cvs_date("$Date: 2016/12/14 20:22:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
script_end_attributes();

 script_summary(english:"checks samba version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("smb_nativelanman.nasl");
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 2\.2\.([0-9]|1[01])[^0-9]*$",string:lanman))
   security_warning(get_kb_item("SMB/transport"));
 else if(ereg(pattern:"Samba 3\.0\.([01]|2|2a)$", string:lanman))
   security_warning(get_kb_item("SMB/transport"));
}
