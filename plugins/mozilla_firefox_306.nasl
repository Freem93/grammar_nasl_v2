#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3004) exit(0);



include("compat.inc");

if (description)
{
  script_id(35581);
  script_version("$Revision: 1.13 $");

  script_cve_id(
    "CVE-2009-0352", 
    "CVE-2009-0353", 
    "CVE-2009-0354", 
    "CVE-2009-0355", 
    "CVE-2009-0356",
    "CVE-2009-0357", 
    "CVE-2009-0358"
  );
  script_bugtraq_id(33598);
  script_osvdb_id(
    51925,
    51926,
    51927,
    51928,
    51929,
    51930,
    51931,
    51932,
    51933,
    51934,
    51935,
    51936,
    51937,
    51938,
    51939,
    51940
  );

  script_name(english:"Firefox 3.0.x < 3.0.6 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox 3.0.x is earlier than 3.0.6.  Such
versions are potentially affected by the following security issues :

  - There are several stability bugs in the browser engine
    that could lead to crashes with evidence of memory 
    corruption. (MFSA 2009-01)

  - A chrome XBL method can be used in conjunction with 
    'window.eval' to execute arbitrary JavaScript within 
    the context of another website, violating the same 
    origin policy. (MFSA 2009-02)

  - A form input control's type could be changed during the
    restoration of a closed tab to the path of a local file
    whose location was known to the attacker. (MFSA 2009-03)

  - An attacker may be able to inject arbitrary code into a
    chrome document and then execute it with chrome 
    privileges if he can trick a user into downloading a 
    malicious HTML file and a .desktop shortcut file. 
    (MFSA 2009-04)

  - Cookies marked HTTPOnly are readable by JavaScript via
    the 'XMLHttpRequest.getResponseHeader' and 
    'XMLHttpRequest.getAllResponseHeaders' APIs. 
    (MFSA 2009-05)

  - The 'Cache-Control: no-store' and 'Cache-Control: 
    no-cache' HTTP directives for HTTPS pages are ignored 
    by Firefox 3, which could lead to exposure of 
    sensitive information. (MFSA 2009-06)" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-02.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-03.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-04.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-05.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-06.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 3.0.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(59, 79, 200, 264, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/04");
 script_set_attribute(attribute:"patch_publication_date", value: "2009/02/03");
 script_cvs_date("$Date: 2016/11/28 21:52:56 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}


include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.0.6', min:'3.0', severity:SECURITY_HOLE);