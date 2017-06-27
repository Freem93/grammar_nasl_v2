#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15705);
 script_version ("$Revision: 1.17 $");

 script_cve_id("CVE-2004-0882", "CVE-2004-0930");
 script_bugtraq_id(11624, 11678);
 script_osvdb_id(11555, 11782);

 script_name(english: "Samba Multiple Remote Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote Samba server, according to its version number, is affected
by a remote denial of service vulnerability as well as a buffer
overflow. 

The Wild Card DoS vulnerability may allow an attacker to make the
remote server consume excessive CPU cycles. 

The QFILEPATHINFO Remote buffer overflow vulnerability may allow an
attacker to execute code on the server. 

An attacker needs a valid account or enough credentials to exploit
those flaws." );
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2004-0882.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2004-0930.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 3.0.8 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/09");
 script_cvs_date("$Date: 2016/12/14 20:22:11 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/09/13");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
 script_end_attributes();

 script_summary(english: "checks samba version");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english: "Misc.");
 if ( !defined_func("bn_random"))
 	script_dependencie("smb_nativelanman.nasl");
 else
	script_dependencie("smb_nativelanman.nasl");
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

if ( get_kb_item("CVE-2004-0930") ) exit(0);

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 3\.0\.[0-7]$", string:lanman))security_hole(139);
}
