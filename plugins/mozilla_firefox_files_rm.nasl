#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15408);
 script_version("$Revision: 1.18 $");
 script_cve_id("CVE-2004-2225");
 script_bugtraq_id(11311);
 script_osvdb_id(10478);

 script_name(english:"Firefox < 0.10.1 Download Directory Arbitrary File Deletion");
 script_summary(english:"Determines the version of Firefox");

 script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
an arbitrary file deletion vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The installed version of Firefox is earlier than 0.10.1.  Such
versions contain a weakness that could allow a remote attacker
to delete arbitrary files in the user download directory.  To
exploit this, an attacker would need to trick a user into viewing
a malicious web page." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.mozilla.org/press/mozilla-2004-10-01-02.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Firefox 0.10.1 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/29");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/10/01");
 script_cvs_date("$Date: 2013/05/23 15:37:58 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Firefox/version");
 script_require_ports(139, 445);
 exit(0);
}

include("mozilla_version.inc");

port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'0.10.1', severity:SECURITY_WARNING);
