#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95883);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/08 14:08:13 $");

  script_cve_id(
    "CVE-2016-9893",
    "CVE-2016-9895",
    "CVE-2016-9897",
    "CVE-2016-9898",
    "CVE-2016-9899",
    "CVE-2016-9900",
    "CVE-2016-9901",
    "CVE-2016-9902",
    "CVE-2016-9904",
    "CVE-2016-9905"
  );
  script_bugtraq_id(
    94884,
    94885
  );
  script_osvdb_id(
    148666,
    148667,
    148668,
    148693,
    148695,
    148696,
    148697,
    148698,
    148699,
    148700,
    148701,
    148704,
    148705,
    148706,
    148707,
    148708,
    148709,
    148710,
    148711
  );
  script_xref(name:"MFSA", value:"2016-95");
  script_xref(name:"EDB-ID", value:"41042");

  script_name(english:"Mozilla Firefox ESR 45.x < 45.6 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS or Mac OS X host contains a web browser that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR installed on the remote macOS or
Mac OS X host is 45.x prior to 45.6. It is, therefore, affected by
the following vulnerabilities :

  - Multiple memory corruption issues exist, such as when
    handling document state changes or HTML5 content, or
    else due to dereferencing already freed memory or
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-9893)

  - A security bypass vulnerability exists due to event
    handlers for marquee elements being executed despite a
    Content Security Policy (CSP) that disallowed inline
    JavaScript. An unauthenticated, remote attacker can
    exploit this to impact integrity. (CVE-2016-9895)

  - A memory corruption issue exists in libGLES when WebGL
    functions use a vector constructor with a varying array
    within libGLES. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition or
    the execution of arbitrary code. (CVE-2016-9897)

  - A use-after-free error exists in Editor, specifically
    within file editor/libeditor/HTMLEditor.cpp, when
    handling DOM subtrees. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-9898)

  - A use-after-free error exists in the
    nsNodeUtils::CloneAndAdopt() function within file
    dom/base/nsNodeUtils.cpp, while manipulating DOM events
    and removing audio elements, due to improper handling of
    failing node adoption. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-9899)

  - A security bypass vulnerability exists in the
    nsDataDocumentContentPolicy::ShouldLoad() function
    within file dom/base/nsDataDocumentContentPolicy.cpp
    that allows external resources to be inappropriately
    loaded by SVG images by utilizing 'data:' URLs. An
    unauthenticated, remote attacker can exploit this to
    disclose sensitive cross-domain information.
    (CVE-2016-9900)

  - A flaw exists due to improper sanitization of HTML tags
    received from the Pocket server. An unauthenticated,
    remote attacker can exploit this to run JavaScript code
    in the about:pocket-saved (unprivileged) page, giving it
    access to Pocket's messaging API through HTML injection.
    (CVE-2016-9901)

  - A flaw exists in the Pocket toolbar button, specifically
    in browser/extensions/pocket/content/main.js, due to
    improper verification of the origin of events fired from
    its own pages. An unauthenticated, remote attacker can
    exploit this to inject content and commands from other
    origins into the Pocket context. Note that this issue
    does not affect users with e10s enabled. (CVE-2016-9902)

  - An information disclosure vulnerability exists that
    allows an unauthenticated, remote attacker to determine
    whether an atom is used by another compartment or zone
    in specific contexts, by utilizing a JavaScript Map/Set
    timing attack. (CVE-2016-9904)

  - A memory corruption issue exists in the
    nsDocument::EnumerateSubDocuments() function within file
    dom/base/nsDocument.cpp when adding and removing
    sub-documents. An unauthenticated, remote attacker can
    exploit this, via a specially crafted web page, to cause
    a denial of service condition or the execution of
    arbitrary code. (CVE-2016-9905)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-95/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 45.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

is_esr = get_kb_item(kb_base+"/is_esr");
if (isnull(is_esr)) audit(AUDIT_NOT_INST, "Mozilla Firefox ESR");

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'45.6', min:'45.0', severity:SECURITY_HOLE);
