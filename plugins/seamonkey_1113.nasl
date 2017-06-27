#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34768);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2008-0017", "CVE-2008-4582", "CVE-2008-5012", "CVE-2008-5013",
                "CVE-2008-5014", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018",
                "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024",
                "CVE-2008-5052", "CVE-2008-6961");
  script_bugtraq_id(31747, 32281, 32351, 32363);
    script_osvdb_id(
      49073,
      49925,
      49995,
      50139,
      50140,
      50141,
      50176,
      50177,
      50179,
      50181,
      50182,
      50210,
      50285,
      57003
    );
    script_xref(name:"Secunia", value:"32714");
  if (NASL_LEVEL >= 3000)
  {
  }

  script_name(english:"SeaMonkey < 1.1.13 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis", value:
"A web browser on the remote host is affected by multiple
vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey is earlier than 1.1.13.  Such
versions are potentially affected by the following security issues :

  - Locally saved '.url' shortcut files can be used to read
    information stored in the local cache. (MFSA 2008-47)

  - The canvas element can be used in conjunction with an 
    HTTP redirect to bypass same-origin restrictions and 
    gain access to the content in arbitrary images from 
    other domains. (MFSA 2008-48)

  - Arbitrary code execution is possible via Flash Player 
    dynamic module unloading. (MFSA 2008-49)

  - By tampering with the window.__proto__.__proto__ object, 
    one can cause the browser to place a lock on a non-
    native object, leading to a crash and possible code
    execution. (MFSA 2008-50)

  - There are several stability bugs in the browser engine
    that may lead to crashes with evidence of memory 
    corruption. (MFSA 2008-52)

  - There is a buffer overflow that can be triggered by 
    sending a specially crafted 200 header line in the HTTP
    index response. (MFSA 2008-54)

  - Crashes and remote code execution in nsFrameManager are
    possible by modifying certain properties of a file 
    input element before it has finished initializing.
    (MFSA 2008-55)

  - The same-origin check in 
    'nsXMLHttpRequest::NotifyEventListeners()' can be 
    bypassed. (MFSA 2008-56)

  - The '-moz-binding' CSS property can be used to bypass
    security checks which validate codebase principals.
    (MFSA 2008-57)

  - There is an error in the method used to parse the 
    default namespace in an E4X document caused by quote 
    characters in the namespace not being properly escaped.
    (MFSA 2008-58)

  - Scripts in a malicous mail message can access the 
    .document URI and .textContext. DOM properties.
    (MFSA 2008-59)" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-47.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-48.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-49.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-50.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-52.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-54.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-55.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-56.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-57.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-58.html" );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-59.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to SeaMonkey 1.1.13 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 94, 119, 189, 200, 264, 287, 399);
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/11/13");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'1.1.13', severity:SECURITY_HOLE);