#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(1, "The plugin description is longer than 3191 characters.");

include("compat.inc");

if (description)
{
  script_id(49148);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id("CVE-2010-2760", "CVE-2010-2762", "CVE-2010-2764", "CVE-2010-2765",
                "CVE-2010-2766", "CVE-2010-2767", "CVE-2010-2768", "CVE-2010-2769",
                "CVE-2010-2770", "CVE-2010-3131", "CVE-2010-3166", "CVE-2010-3167",
                "CVE-2010-3168", "CVE-2010-3169");
  script_bugtraq_id(42654, 43091, 43092, 43093, 43095, 43096, 43097,
                    43100, 43101, 43102, 43104, 43106, 43108, 43118);
  script_osvdb_id(
    66601,
    67502,
    67900,
    67902,
    67903,
    67904,
    67905,
    67906,
    67907,
    67908,
    67910,
    67911,
    67912,
    67913
  );
  script_xref(name:"Secunia", value:"41304");

  script_name(english:"Mozilla Thunderbird 3.1 < 3.1.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird 3.1 is earlier than 3.1.3.  Such
versions are potentially affected by the following security issues :

  - Multiple memory safety bugs could lead to memory
    corruption, potentially resulting in arbitrary
    code execution. (MFSA 2010-49)

  - An integer overflow vulnerability in HTML frameset element
    implementation could lead to arbitrary code execution.
    (MFSA 2010-50)

  - A dangling pointer vulnerability in 'navigator.plugins'
    could lead to arbitrary code execution. (MFSA 2010-51)

  - It is possible to perform DLL hijacking attacks via
    dwmapi.dll. (MFSA 2010-52)

  - A heap overflow vulnerability in function
    'nsTextFrameUtils::TransformText' could result in
    arbitrary code execution on the remote system.
    (MFSA 2010-53)

  - A dangling pointer vulnerability reported in
    MFSA 2010-40 was incorrectly fixed. (MFSA 2010-54)

  - By manipulating XUL <tree> objects it may be possible
    to crash the application or run arbitrary code on the
    remote system. (MFSA 2010-55)

  - A dangling pointer vulnerability affects XUL <tree>'s
    content view implementation, which could allow arbitrary
    code execution on the remote system. (MFSA 2010-56)

  - Code used to normalize a document could lead to a crash
    or arbitrary code execution on the remote system.
    (MFSA 2010-57)

  - A specially crafted font could trigger memory corruption
    on Mac systems, potentially resulting in arbitrary code
    execution on the remote system. (MFSA 2010-58)

  - It may be possible to run arbitrary JavaScript with
    chrome privileges via wrapper class XPCSafeJSObjectWrapper
    (SJOW). (MFSA 2010-59)

  - The 'type' attribute of an <object> tag could override
    charset of a framed HTML document, which could allow
    an attacker to inject and execute UTF-7 encoded
    JavaScript code into a website. (MFSA 2010-61)

  - Copy-and-paste or drag-and-drop of an HTML selection
    containing JavaScript into a designMode document
    could trigger a cross-site scripting vulnerability.
    (MFSA 2010-62)

  - It is possible to read sensitive information via
    'statusText' property of an XMLHttpRequest object.
    (MFSA 2010-63)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-49.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-50.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-51.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-52.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-53.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-54.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-55.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-56.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-57.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-58.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-59.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-61.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-62.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-63.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/known-vulnerabilities/thunderbird31.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 3.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'3.1.3', min:'3.1.0', severity:SECURITY_HOLE);