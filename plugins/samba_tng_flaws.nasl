#
# (C) Tenable Network Security, Inc.
#

# Ref: 
#
# Date: Sat, 22 Mar 2003 21:03:11 +0100 (CET)
# From: Stephan Lauffer <lauffer@ph-freiburg.de>
# To: tng-announcements@lists.dcerpc.org
# Cc: tng-technical@lists.dcerpc.org, <tng-users@lists.dcerpc.org>
# Subject: [ANNOUNCE] Samba-TNG 0.3.1 Security Release

include("compat.inc");

if (description)
{
 script_id(11442);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2012/08/16 00:34:44 $");

 script_cve_id("CVE-2003-0085");
 script_bugtraq_id(7106, 7206);
 script_osvdb_id(6323, 57172);

 script_name(english: "Samba TNG < 0.3.1 Multiple Remote Vulnerabilities");
 script_summary(english: "checks samba version");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"The remote Samba server, according to its version number, is vulnerable 
to multiple flaws that could let an attacker gain a root shell on this 
host.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba TNG 0.3.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/22");
 script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/27");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");
 script_family(english: "Gain a shell remotely");
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
 if(ereg(pattern:"Samba TNG-alpha$", string:lanman))security_hole(139);
}
