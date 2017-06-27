#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26068);
  script_version("$Revision: 1.10 $");
  script_cve_id("CVE-2006-4965");
  script_osvdb_id(29064);

  script_name(english:"Firefox < 2.0.0.7 Apple QuickTime Plug-In .qtl File qtnext Field Cross-context Scripting");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that may allow
arbitrary code execution." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox may allow a remote attacker to run
script commands subject to the user's privileges via 'qtnext'
attributes in QuickTime Media-Link files. 

Note that this issue can be exploited even if support for JavaScript
in the browser has been disabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-28.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cwe_id(94);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/20");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/09/18");
 script_cvs_date("$Date: 2013/05/23 15:37:57 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'2.0.0.7', severity:SECURITY_HOLE);