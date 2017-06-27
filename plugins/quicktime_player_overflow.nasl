#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11506);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2003-0168");
 script_bugtraq_id(7247);
 script_osvdb_id(10561);
 
 script_name(english: "QuickTime < 6.1 URL Handling Overflow (Windows)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote version of the QuickTime player is vulnerable to
a buffer overflow.

To exploit it, an attacker would need a user of this host to
visit a rogue webpage with a malformed link in it. He could
then be able to execute arbitrary code with the rights of the user
visiting the page." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to QuickTime Player version 6.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/03/31");
 script_cvs_date("$Date: 2011/04/13 16:19:07 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
script_end_attributes();

 script_summary(english: "Checks the version of QuickTime Player");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english: "Windows");
 
 script_dependencies("quicktime_installed.nasl");
 script_require_keys("SMB/QuickTime/Version");

 exit(0);
}


ver = get_kb_item("SMB/QuickTime/Version");
if (ver && ver =~ "^([0-5]\.|6\.0\.)") security_hole(get_kb_item("SMB/transport"));
