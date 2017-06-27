#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14381);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2004-0829");
 script_bugtraq_id(11055);
 script_osvdb_id(9362);

 script_name(english: "Samba smbd FindNextPrintChangeNotify() Request Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote Samba server, according to its version number, is vulnerable 
to a denial of service.

An attacker may be able to crash the remote samba server by sending a 
FindNextPrintChangeNotify() request without previously issuing a 
FindFirstPrintChangeNoticy() call.

It is reported that Windows XP SP2 generates such requests." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 2.2.11 or 3.0.6" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/12");
 script_cvs_date("$Date: 2011/04/13 18:23:00 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
script_end_attributes();

 script_summary(english: "checks samba version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english: "Denial of Service");
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
 if(ereg(pattern:"Samba 2\.2\.([0-9][^0-9]*|10)$",
 	 string:lanman))security_warning(139);
 else if(ereg(pattern:"Samba 3\.0\.[0-5][^0-9]*$",
 	 string:lanman))security_warning(139);
}
