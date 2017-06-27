#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16085);
 script_version("$Revision: 1.21 $");

 script_cve_id("CVE-2004-1316");
 script_bugtraq_id(12131, 12407);
 script_osvdb_id(12637);

 script_name(english:"Mozilla nsNNTPProtocol.cpp NNTP news:// URI Handling Overflow DoS");

 script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is prone to a heap overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote version of Mozilla is vulnerable to a heap overflow attack
against its NNTP functionality. 

This may allow an attacker to execute arbitrary code on the remote
host. 

To exploit this flaw, an attacker would need to set up a rogue news
site and lure a victim on the remote host into reading news from it." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2005/mfsa2005-06.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla 1.7.5 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/29");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/12/24");
 script_cvs_date("$Date: 2013/05/23 15:37:58 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:mozilla");
script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:thunderbird");
script_end_attributes();

 script_summary(english:"Determines the version of Mozilla");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Version");
 exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'1.7.5', severity:SECURITY_HOLE);
