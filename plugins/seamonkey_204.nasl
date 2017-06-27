#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45395);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2010-0173",
    "CVE-2010-0174",
    "CVE-2010-0175",
    "CVE-2010-0176",
    "CVE-2010-0177",
    "CVE-2010-0178",
    "CVE-2010-0181",
    "CVE-2010-0182"
  );
  script_bugtraq_id(
    36935, 
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
    63460,
    63461,
    63462,
    63463,
    63464,
    63465,
    63466,
    63620
  );
  script_xref(name:"Secunia", value:"39136");

  script_name(english:"SeaMonkey < 2.0.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description",value:
"The installed version of SeaMonkey is earlier than 2.0.4.  Such
versions are potentially affected by the following security issues :

  - Multiple crashes can result in arbitrary code execution.
    (MFSA 2010-16)

  - A select event handler for XUL tree items can be called
    after the item is deleted. (MFSA 2010-17)

  - An error exists in the way '<option>' elements are 
    inserted into an XUL tree '<optgroup>' (MFSA 2010-18)

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
    
  - XML Documents fail to call certain security checks when
    loading new content. (MFSA 2010-24)"
  );
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-16.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-17.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-18.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-19.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-20.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-22.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-23.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-24.html");
  script_set_attribute(attribute:"solution",value:"Upgrade to SeaMonkey 2.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(310);
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/03/30");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/03/31");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.0.4', severity:SECURITY_HOLE);