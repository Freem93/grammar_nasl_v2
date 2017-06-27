#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14686);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2004-1666");
 script_bugtraq_id(11142);
 script_osvdb_id(9777);

 name["english"] = "Trillian MSN Overflow";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"Trillian is a Peer2Peer client that allows users to chat and 
share files with other users across the world.  A bug has been 
reported in the MSN portion of Trillian.  

A remote attacker, exploiting this flaw, would be potentially 
able to execute code on the client system running Trillian." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Trillian 0.74 patch J (or higher)." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/08");
 script_cvs_date("$Date: 2011/04/13 20:23:35 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:trillian:trillian");
 script_end_attributes();
 
 summary["english"] = "Determines the version of Trillian.exe";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("trillian_patchg.nasl");
 script_require_keys("Host/Windows/Trillian/Version");
 exit(0);
}


version = get_kb_item("Host/Windows/Trillian/Version");

if (egrep(string:version, pattern:"v0\.7[1-4].*")) {
    if (! egrep(string:version, pattern:"\(w/ Patch [J-Z]\)")) security_hole(get_kb_item("SMB/transport"));
}
