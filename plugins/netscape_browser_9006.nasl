#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31135);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", 
                "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0420",
                "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");
  script_bugtraq_id(24293, 27406, 27683, 27826);
  script_osvdb_id(
    41187,
    41215,
    41217,
    41218,
    41220,
    41221,
    41222,
    41223,
    41224,
    41225,
    42057,
    43226,
    43456,
    43457,
    43458,
    43459,
    43460,
    43461,
    43462
  );
  script_xref(name:"Secunia", value:"29049");

  script_name(english:"Netscape Browser < 9.0.0.6 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Netscape");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Netscape is affected by various security
issues :

  - Several stability bugs leading to crashes which, in
    some cases, show traces of memory corruption.

  - Several file input focus stealing vulnerabilities
    that could result in uploading of arbitrary files
    provided their full path and file names are known.

  - Several issues that allow scripts from page content 
    to escape from their sandboxed context and/or run 
    with chrome privileges, resulting in privilege 
    escalation, XSS, and/or remote code execution.

  - An issue that could allow a malicious site to inject
    newlines into the application's password store when
    a user saves a password, resulting in corruption of
    saved passwords for other sites.  

  - A directory traversal vulnerability via the 
    'chrome:' URI.

  - A vulnerability involving 'designMode' frames that
    may result in web browsing history and forward 
    navigation stealing.

  - An information disclosure issue in the BMP 
    decoder.

  - A file action dialog tampering vulnerability
    involving timer-enabled security dialogs.

  - Mis-handling of locally-saved plaintext files.

  - Possible disclosure of sensitive URL parameters,
    such as session tokens, via the .href property of 
    stylesheet DOM nodes reflecting the final URI of 
    the stylesheet after following any 302 redirects.

  - A failure to display a web forgery warning dialog
    in cases where the entire contents of a page are
    enclosed in a '<div>' with absolute positioning." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-02.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-03.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-04.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-05.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-06.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-07.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-08.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-09.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-10.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-11.html" );
   # http://web.archive.org/web/20080406013258/http://browser.netscape.com/releasenotes/9.0.0.6/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03a6d400");
   # http://blog.netscape.com/2007/12/28/end-of-support-for-netscape-web-browsers/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8cae066a" );
 script_set_attribute(attribute:"solution", value:
"The Netscape Browser / Navigator has been discontinued.  While these
issues were reportedly fixed in 9.0.0.6, it is strongly recommended
that you switch to the latest version of another browser, such as
Mozilla Firefox, which the Netscape Team recommends." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 22, 79, 94, 200, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/22");
 script_cvs_date("$Date: 2016/11/23 20:31:33 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:netscape:navigator");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("netscape_browser_detect.nasl");
  script_require_keys("SMB/Netscape/installed");
  exit(0);
}

#

list = get_kb_list("SMB/Netscape/*");
if (isnull(list)) exit(0);

foreach key (keys(list))
{
  ver = key - "SMB/Netscape/";
  if (ver && ver =~ "^([0-8]\.|9\.0($|\.0\.[0-5]))")
  {
    security_hole(get_kb_item("SMB/transport"));
    exit(0);
  }
}
