#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(33563);
  script_version("$Revision: 1.16 $");

  script_cve_id(
    "CVE-2008-2798", 
    "CVE-2008-2799", 
    "CVE-2008-2802", 
    "CVE-2008-2803",
    "CVE-2008-2807", 
    "CVE-2008-2809", 
    "CVE-2008-2811", 
    "CVE-2008-2785"
  );
  script_bugtraq_id(29802, 30038);
  script_osvdb_id(
    46421, 
    46673, 
    46674, 
    46675, 
    46677, 
    46679, 
    46682, 
    46683
  );
  script_xref(name:"Secunia", value:"30915");

  script_name(english:"Mozilla Thunderbird < 2.0.0.16 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."  );
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is affected by various security
issues :

  - Several stability bugs exist leading to crashes which, 
    in some cases, show traces of memory corruption
    (MFSA 2008-21).

  - By taking advantage of the privilege level stored in
    the pre-compiled 'fastload' file, an attacker may be
    able to run arbitrary JavaScript code with chrome
    privileges (MFSA 2008-24).

  - Arbitrary code execution is possible in
    'mozIJSSubScriptLoader.loadSubScript()' (MFSA 2008-25).

  - Several function calls in the MIME handling code
    use unsafe versions of string routines (MFSA 2008-26).

  - An improperly encoded '.properties' file in an add-on
    can result in uninitialized memory being used, which
    could lead to data formerly used by other programs
    being exposed to the add-on code (MFSA 2008-29).

  - A weakness in the trust model regarding alt names on
    peer-trusted certs could lead to spoofing secure
    connections to any other site (MFSA 2008-31).

  - A crash in Mozilla's block reflow code could be used
    by an attacker to crash the browser and run arbitrary
    code on the victim's computer (MFSA 2008-33).

  - By creating a very large number of references to a
    common CSS object, an attacker can overflow the CSS
    reference counter, causing a crash when the browser
    attempts to free the CSS object while still in use
    and allowing for arbitrary code execution
    (MFSA 2008-34)."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-21.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-24.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-25.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-26.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-29.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-31.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-33.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-34.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 2.0.0.16 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 189, 200, 264, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/24");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/07/01");
 script_cvs_date("$Date: 2016/11/28 21:52:57 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'2.0.0.16', severity:SECURITY_HOLE);