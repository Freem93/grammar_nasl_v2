#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45133);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/11/14 18:42:57 $");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2010-0164",
    "CVE-2010-0165",
    "CVE-2010-0167",
    "CVE-2010-0168",
    "CVE-2010-0169",
    "CVE-2010-0170",
    "CVE-2010-0171",
    "CVE-2010-0172",
    "CVE-2010-0173",
    "CVE-2010-0174",
    "CVE-2010-0176",
    "CVE-2010-0177",
    "CVE-2010-0178",
    "CVE-2010-0181",
    "CVE-2010-0182",
    "CVE-2010-1028"
  );
  script_bugtraq_id(
    36935,
    38298,
    38919,
    38920,
    38921,
    38922,
    38927,
    38939,
    38944,
    38946,
    39133,
    39137,
    39122,
    39123,
    39125,
    39128,
    39479
  );
  script_osvdb_id(
    59970,
    62416,
    63264,
    63265,
    63267,
    63268,
    63269,
    63270,
    63271,
    63272,
    63273,
    63460,
    63461,
    63462,
    63463,
    63464,
    63465,
    63466,
    63620
  );
  script_xref(name:"Secunia", value:"38608");

  script_name(english:"Firefox 3.6.x < 3.6.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains a web browser that is affected by
Multiple Vulnerabilities");
  script_set_attribute(attribute:"description",value:
"The installed version of Firefox 3.6.x is earlier than 3.6.2.  Such
versions are potentially affected by multiple security issues :
 
  - The WOFF decoder contains an integer overflow in a font
    decompression routine. (MFSA 2010-08)

  - Deleted image frames are reused when handling
    'multipart/x-mixed-replace' images. (MFSA 2010-09)

  - The 'window.location' object is made a normal 
    overridable object. (MFSA 2010-10)

  - Multiple crashes can result in arbitrary code execution.
    (MFSA 2010-11)

  - A cross-site scripting issue when using
    'addEventListener' and 'setTimeout' on a wrapped object. 
    (MFSA 2010-12)

  - Documents fail to call certain security checks when
    attempting to preload images. (MFSA 2010-13)

  - It is possible to corrupt a user's XUL cache. 
    (MFSA 2010-14)

  - The asynchronous Authorization Prompt is not always
    attached to the correct window. (MFSA 2010-15)
  
  - Multiple crashes can result in arbitrary code execution.
    (MFSA 2010-16)

  - An error exists in the way '<option>' elements are
    inserted into a XUL tree '<optgroup>' (MFSA 2010-18)

  - An error exists in the implementation of the
    'windows.navigator.plugins' object. (MFSA 2010-19)

  - A browser applet can be used to turn a simple mouse
    click into a drag-and-drop action, potentially resulting
    in the unintended loading of resources in a user's
    browser. (MFSA 2010-20)

  - Session renegotiations are not handled properly, which
    can be exploited to insert arbitrary plaintext by a
    man-in-the-middle. (MFSA 2010-22)

  - When an image points to a resource that redirects to a
    'mailto:' URL, the external mail handler application is 
    launched. (MFSA 2010-23)
    
  - XML documents fail to call certain security checks when
    loading new content. (MFSA 2010-024)");
  
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-08.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-09.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-10.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-11.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-12.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-13.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-14.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-15.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-16.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-18.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-19.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-20.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-22.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-23.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-24.html");
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?49ec0d80");
  script_set_attribute(attribute:"solution",value:"Upgrade to Firefox 3.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(310);
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/02/18");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/03/22");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/03/23");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.6.2', min:'3.6', severity:SECURITY_HOLE);