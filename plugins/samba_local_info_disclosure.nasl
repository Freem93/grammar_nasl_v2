#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24684);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2014/05/26 16:30:02 $");

 script_cve_id("CVE-2006-1059");
 script_bugtraq_id(17314);
 script_osvdb_id(24263);

 script_name(english:"Samba winbindd Debug Log Server Credentials Local Disclosure");
 script_summary(english:"Checks the version of Samba");

 script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is vulnerable to a local information
disclosure flaw.");
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote Samba server is affected
by a flaw that may allow a local attacker to get access to the
passwords sent to the winbindd daemon if the debug level has been set
to 5 or higher.");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/429370/100/0/threaded");
 script_set_attribute(attribute:"see_also", value:"http://us1.samba.org/samba/security/CVE-2006-1059.html");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 3.0.22 or set the debug level to a value lower than
5.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

 script_dependencie("smb_nativelanman.nasl");
 script_require_keys("SMB/NativeLanManager", "Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 3\.0\.21($|[a-c]$)", string:lanman))
   security_note(get_kb_item("SMB/transport"));
}
