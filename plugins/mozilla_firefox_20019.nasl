#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35218);
  script_version("$Revision: 1.13 $");

  script_cve_id(
    "CVE-2008-5500", 
    "CVE-2008-5503", 
    "CVE-2008-5504", 
    "CVE-2008-5506", 
    "CVE-2008-5507",
    "CVE-2008-5508", 
    "CVE-2008-5510", 
    "CVE-2008-5511", 
    "CVE-2008-5512", 
    "CVE-2008-5513",
    "CVE-2009-2535"
  );
  script_bugtraq_id(32882, 35446);
  script_osvdb_id(
    51284,
    51285,
    51288,
    51289,
    51291,
    51292,
    51293,
    51294,
    51295,
    51296,
    51297,
    56253
  );

  script_name(english:"Firefox < 2.0.0.19 / 3.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 2.0.0.19.  Such
versions are potentially affected by the following security issues :

  - There are several stability bugs in the browser engine
    that may lead to crashes with evidence of memory 
    corruption. (MFSA 2008-60)

  - XBL bindings can be used to read data from other 
    domains. (MFSA 2008-61)

  - The feed preview still allows for JavaScript privilege
    escalation. (MFSA 2008-62)

  - Sensitive data may be disclosed in an XHR response when
    an XMLHttpRequest is made to a same-origin resource,
    which 302 redirects to a resource in a different 
    domain. (MFSA 2008-64)

  - A website may be able to access a limited amount of 
    data from a different domain by loading a same-domain 
    JavaScript URL which redirects to an off-domain target
    resource containing data which is not parsable as 
    JavaScript. (MFSA 2008-65)

  - Errors arise when parsing URLs with leading whitespace
    and control characters. (MFSA 2008-66)

  - An escaped null byte is ignored by the CSS parser and 
    treated as if it was not present in the CSS input 
    string. (MFSA 2008-67)

  - Cross-site scripting and JavaScript privilege escalation 
    are possible. (MFSA 2008-68)

  - Cross-site scripting vulnerabilities in SessionStore may 
    allow for violating the browser's same-origin policy and 
    performing an XSS attack or running arbitrary 
    JavaScript with chrome privileges. (MFSA 2008-69)

  - Creating a Select object with a very large length can
    result in memory exhaustion, causing a denial of
    service. (CVE-2009-2535)

Note that Mozilla is not planning further security / stability
updates for Firefox 2." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-60.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-61.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-62.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-64.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-65.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-66.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-67.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-68.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-69.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/504969/100/0/threaded" );
 # https://blog.mozilla.org/blog/2008/12/16/firefox-305-and-20019-security-updates-now-available-for-download/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e442733" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.19 / 3.0.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 79, 189, 200, 264, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/12/17");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/12/16");
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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'2.0.0.19', severity:SECURITY_HOLE);