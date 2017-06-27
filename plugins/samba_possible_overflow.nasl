#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID
#
# Refs: o http://lists.samba.org/pipermail/samba-technical/2002-June/037400.html
#       o FreeBSD-SN-02:05
#
# Only Samba 2.2.4 is affected by this.
#


include("compat.inc");

if(description)
{
 script_id(11113);
 script_version ("$Revision: 1.20 $");
 script_cvs_date("$Date: 2011/04/13 18:23:00 $");

 script_cve_id("CVE-2002-2196");
 script_bugtraq_id(5587);
 script_osvdb_id(861);
 script_xref(name:"SuSE", value:"SUSE-SA:2002:045");

 script_name(english:"Samba enum_csc_policy Data Structure Termination Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote Samba server may be affected by a buffer overflow issue." );
 script_set_attribute(attribute:"description", value:
"The remote Samba server, according to its version number, is
vulnerable to a possible buffer overflow because it fails to properly
terminate the 'enum_csc_policy' struct." );
 script_set_attribute(attribute:"see_also", value:"http://lists.samba.org/archive/samba-technical/2002-June/022075.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-2.2.5.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba 2.2.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/06/13");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
script_end_attributes();

 
 script_summary(english:"checks samba version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2011 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("smb_nativelanman.nasl");
 script_require_ports(139);
 script_require_keys("SMB/NativeLanManager");
 exit(0);
}

#
# The script code starts here
#

lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
 if(ereg(pattern:"Samba 2\.2\.4[^0-9]*$",
 	 string:lanman))security_hole(139);
}
