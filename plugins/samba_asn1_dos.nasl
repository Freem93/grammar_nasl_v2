#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14711);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2004-0807", "CVE-2004-0808");
 script_bugtraq_id(11156);
 script_osvdb_id(9916, 9917);

 script_name(english:"Samba < 3.0.7 Multiple Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote Samba server, according to its version number, is 
vulnerable to a denial of service.

There is a bug in the remote smbd ASN.1 parsing that could allow an 
attacker to cause a denial of service attack against the remote host 
by sending a specially crafted ASN.1 packet during the authentication 
request that could make the newly-spawned smbd process run into an 
infinite loop. By establishing multiple connections and sending such 
packets, an attacker could consume all the CPU and memory of the 
remote host, thus crashing it remotely.

Another bug could allow an attacker to crash the remote nmbd process 
by sending a malformed NetBIOS packet." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 3.0.7." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/13");
 script_cvs_date("$Date: 2012/06/19 21:49:20 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
script_end_attributes();

 script_summary(english: "checks samba version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
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
 if(ereg(pattern:"Samba 3\.0\.[0-6][^0-9]*$",
 	 string:lanman))security_warning(139);
}
