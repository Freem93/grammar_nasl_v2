#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(14197);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2004-0760");
 script_bugtraq_id(10709);
 script_osvdb_id(8307);

 script_name(english:"Firefox < 0.9.3 Null Character MIME Type Spoofing Arbitrary Code Execution");
 script_summary(english:"Determines the version of Firefox");

 script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains a web browser that has a code
execution vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The installed version of Firefox is earlier than 0.9.3.  Such
versions may allow arbitrary code execution.

The security vulnerability is due to the fact that Firefox stores
cached HTML documents with a known file name, and to the fact that
it's possible to force Firefox to open cached files as HTML documents
by appending a NULL byte after the file name.

A remote attacker may combine these two flaws to execute arbitrary
code on the remote host." );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Firefox 0.9.3 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/03");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/08/04");

 script_cvs_date("$Date: 2014/05/05 21:37:03 $");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Firefox/Version");
 exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'0.9.2', severity:SECURITY_HOLE);
