#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45392);
  script_version("$Revision: 1.13 $");

  script_cve_id(
    "CVE-2010-0173",
    "CVE-2010-0174",
    "CVE-2010-0175",
    "CVE-2010-0176",
    "CVE-2010-0177",
    "CVE-2010-0178",
    "CVE-2010-0179"
  );
  script_bugtraq_id(39122, 39123, 39124, 39125, 39128, 39133, 39137);
  script_osvdb_id(63460, 63461, 63462, 63463, 63464, 63465, 63637);
  script_xref(name:"Secunia", value:"39240");

  script_name(english:"Firefox < 3.0.19 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description",value:
"The installed version of Firefox is earlier than 3.0.19.  Such
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

  - The XMLHttpRequestSpy module in the Firebug add-on 
    exposes an underlying chrome privilege escalation
    vulnerability. (MFSA 2010-21)"
  );
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-16.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-17.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-18.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-19.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-20.html");
  script_set_attribute(attribute:"see_also",value:"http://www.mozilla.org/security/announce/2010/mfsa2010-21.html");
  script_set_attribute(attribute:"solution",value:"Upgrade to Firefox 3.0.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/03/30");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/03/31");
 script_cvs_date("$Date: 2014/09/24 14:12:00 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.0.19', severity:SECURITY_HOLE);