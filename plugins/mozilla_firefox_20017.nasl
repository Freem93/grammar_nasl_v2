#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if (description)
{
  script_id(34268);
  script_version("$Revision: 1.17 $");

  script_cve_id(
    "CVE-2008-0016", 
    "CVE-2008-3835", 
    "CVE-2008-3836", 
    "CVE-2008-3837", 
    "CVE-2008-4058",
    "CVE-2008-4059", 
    "CVE-2008-4060", 
    "CVE-2008-4061", 
    "CVE-2008-4062", 
    "CVE-2008-4063",
    "CVE-2008-4064", 
    "CVE-2008-4065", 
    "CVE-2008-4066", 
    "CVE-2008-4067", 
    "CVE-2008-4068",
    "CVE-2008-4069"
  );
  script_bugtraq_id(31346, 31397);
  script_osvdb_id(
    48746,
    48747,
    48748,
    48749,
    48750,
    48751,
    48759,
    48760,
    48761,
    48762,
    48763,
    48764,
    48765,
    48766,
    48767,
    48768,
    48769,
    48770,
    48771,
    48773,
    48779,
    48780,
    48782,
    56782
  );
  script_xref(name:"Secunia", value:"31984");

  script_name(english:"Firefox < 2.0.0.17 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues :

  - Using a specially crafted UTF-8 URL in a hyperlink, an
    attacker might be able to exploit a stack buffer 
    overflow in the Mozilla URL parsing routes to execute
    arbitrary code (MFSA 2008-37).

  - It is possible to bypass the same-origin check in 
    'nsXMLDocument::OnChannelRedirect()' (MFSA 2008-38).

  - There are a series of vulnerabilities in 'feedWriter' 
    that allow scripts from page content to run with chrome
    privileges (MFSA 2008-39).

  - An attacker can cause the content window to move while
    the mouse is being clicked, causing an item to be 
    dragged rather than clicked-on (MFSA 2008-40).

  - Privilege escalation is possible via 'XPCnativeWrapper'
    pollution (MFSA 2008-41).

  - There are several stability bugs in the browser engine
    that may lead to crashes with evidence of memory 
    corruption (MFSA 2008-42).

  - Certain BOM characters and low surrogate characters,
    if HTML-escaped, are stripped from JavaScript code
    before it is executed, which could allow for cross-
    site scripting attacks (MFSA 2008-43).

  - The 'resource:' protocol allows directory traversal 
    on Linux when using URL-encoded slashes, and it can
    by used to bypass restrictions on local HTML files
    (MFSA 2008-44).

  - A bug in the XBM decoder allows random small chunks of
    uninitialized memory to be read (MFSA 2008-45)." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-37.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-38.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-39.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-40.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-41.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-42.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-43.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-44.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-45.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.17 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(22, 79, 119, 189, 200, 264, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/09/23");
 script_cvs_date("$Date: 2016/11/28 21:52:56 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'2.0.0.17', severity:SECURITY_HOLE);