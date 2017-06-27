#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(16245);
 script_version("$Revision: 1.12 $");
 script_bugtraq_id(12344);
 script_osvdb_id(13274);
 script_xref(name:"Secunia", value:"14026");

 script_name(english:"Citadel/UX select() Bitmap Array Index Remote Oerflow");
 script_summary(english:"Checks the version of the remote Citadel server");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote messaging service has a buffer overflow vulnerability."
 );
 script_set_attribute( attribute:"description", value:
"The remote host is running Citadel/UX, a messaging server for Unix.

The remote version of this software is vulnerable to a buffer overflow
when performing a select() system call while providing very high file
descriptors. A remote attacker may exploit this flaw to modify at
least one byte in memory.  This could lead to a denial of service, or
possibly arbitrary code execution." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/fulldisclosure/2005/Jan/726"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2005/Jan/301"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Citadel 6.29 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/26");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_dependencies("citadel_overflow.nasl");
 script_require_ports("Services/citadel/ux", 504);
 exit(0);
}


port = get_kb_item("Services/citadel/ux");
if ( ! port ) port = 504;

kb = get_kb_item("citadel/" + port + "/version");
if ( ! kb ) exit(0);


version = egrep(pattern:"^Citadel(/UX)? ([0-5]\..*|6\.([0-1][0-9]|2[0-8])[^0-9])", string:kb);

if ( version )
	security_hole(port);

