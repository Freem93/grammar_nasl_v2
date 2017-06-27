#
# (C) Tenable Network Security, Inc.
#

# Ref: 
# From: Wichert Akkerman <wichert@wiggy.net>
# Subject: [SECURITY] [DSA-262-1] samba security fix
# Resent-Message-ID: <VvQa6C.A.oDH.Ng1c-@murphy>
# To: bugtraq@securityfocus.com
#

include("compat.inc");

if(description)
{
 script_id(11398);
 script_version ("$Revision: 1.20 $");

 script_cve_id("CVE-2003-0085", "CVE-2003-0086");
 script_bugtraq_id(7106, 7107);
 script_osvdb_id(6323, 12642);
 script_xref(name:"RHSA", value:"2003:095-03");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:016");

 script_name(english: "Samba < 2.2.8 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote Samba server, according to its version number, is vulnerable
to a remote buffer overflow when receiving specially crafted SMB 
fragment packets.

An attacker needs to be able to access at least one share to exploit 
this flaw.

In addition, it is reported that Samba contains a flaw
related to the handling of .reg files that may allow
a local user to overwrite arbitrary file." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 2.2.8." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/03/15");
 script_cvs_date("$Date: 2014/05/02 03:09:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
script_end_attributes();

 script_summary(english: "checks samba version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
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
 if(ereg(pattern:"Samba 2\.(0\..*|2\.[0-7][^0-9].*)", string:lanman))security_hole(139);
}
