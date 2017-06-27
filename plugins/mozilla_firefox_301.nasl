#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33522);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2008-2785", "CVE-2008-2933", "CVE-2008-3198");
  script_bugtraq_id(29802, 30242, 30244);
  script_osvdb_id(46421, 47465, 48782);

  script_name(english:"Firefox 3.x < 3.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues :

  - By creating a very large number of references to a 
    common CSS object, an attacker can overflow the CSS
    reference counter, causing a crash when the browser 
    attempts to free the CSS object while still in use
    and allowing for arbitrary code execution
    (MFSA 2008-34).

  - If Firefox is not already running, passing it a
    command-line URI with pipe ('|') symbols will open 
    multiple tabs, which could be used to launch 
    'chrome:i' URIs from the command-line or to pass URIs
    to Firefox that would normally be handled by a vector 
    application (MFSA 2008-35)." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-34.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-35.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 3.0.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 94, 189);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/17");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/07/15");
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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.0.1', min:'3.0', severity:SECURITY_HOLE);