#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33393);
  script_version("$Revision: 1.12 $");

  script_cve_id(
   "CVE-2008-2798", 
   "CVE-2008-2799", 
   "CVE-2008-2800", 
   "CVE-2008-2801", 
   "CVE-2008-2802", 
   "CVE-2008-2803", 
   "CVE-2008-2805", 
   "CVE-2008-2806", 
   "CVE-2008-2807", 
   "CVE-2008-2808",
   "CVE-2008-2809", 
   "CVE-2008-2810", 
   "CVE-2008-2811"
  );
  script_bugtraq_id(30038);
  script_osvdb_id(
    46673,
    46674,
    46675,
    46676,
    46677,
    46678,
    46679,
    46680,
    46681,
    46682,
    46683,
    46684,
    46685,
    46686,
    46687,
    46688
  );
  script_xref(name:"Secunia", value:"30911");

  script_name(english:"Firefox < 2.0.0.15 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues :

  - Several stability bugs leading to crashes which, in
    some cases, show traces of memory corruption
    (MFSA 2008-21).

  - A vulnerability involving violation of the same-origin 
    policy could allow for cross-site scripting attacks
    (MFSA 2008-22).

  - JavaScript can be injected into the context of signed 
    JARs and executed under the context of the JAR's signer
    (MFSA 2008-23).

  - By taking advantage of the privilege level stored in 
    the pre-compiled 'fastload' file, an attacker may be
    able to run arbitrary JavaScript code with chrome 
    privileges (MFSA 2008-24).

  - Arbitrary code execution is possible in 
    'mozIJSSubScriptLoader.loadSubScript()' (MFSA 2008-25).

  - An attacker can steal files from known locations on a 
    victim's computer via originalTarget and DOM Range
    (MFSA 2008-27).

  - It is possible for a malicious Java applet to bypass 
    the same-origin policy and create arbitrary socket 
    connections to other domains (MFSA 2008-28).

  - An improperly encoded '.properties' file in an add-on 
    can result in uninitialized memory being used, which
    could lead to data formerly used by other programs
    being exposed to the add-on code (MFSA 2008-29).

  - File URLs in directory listings are not properly HTML-
    escaped when the filenames contained particular 
    characters (MFSA 2008-30).

  - A weakness in the trust model regarding alt names on 
    peer-trusted certs could lead to spoofing secure 
    connections to any other site (MFSA 2008-31).

  - URL shortcut files on Windows (for example, saved IE 
    favorites) could be interpreted as if they were in the 
    local file context when opened by Firefox, although 
    the referenced remote content would be downloaded and 
    displayed (MFSA 2008-32).

  - A crash in Mozilla's block reflow code could be used 
    by an attacker to crash the browser and run arbitrary 
    code on the victim's computer (MFSA 2008-33)." );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-21.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-22.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-23.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-24.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-25.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-27.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-28.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-29.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-30.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-31.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-32.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-33.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.15 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(20, 79, 200, 264, 287, 399);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/02");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/07/01");
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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'2.0.0.15', severity:SECURITY_HOLE);