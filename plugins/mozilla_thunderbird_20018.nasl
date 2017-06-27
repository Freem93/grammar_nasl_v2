#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(34819);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_cve_id(
    "CVE-2008-5012", 
    "CVE-2008-5014", 
    "CVE-2008-5016", 
    "CVE-2008-5017",
    "CVE-2008-5018", 
    "CVE-2008-5021", 
    "CVE-2008-5022", 
    "CVE-2008-5024",
    "CVE-2008-5052", 
    "CVE-2008-6961"
  );
  script_bugtraq_id(32281, 32351, 32363);
  script_osvdb_id(
    49995,
    50139,
    50141,
    50176,
    50177,
    50179,
    50181,
    50210,
    50285,
    57003
  );
  script_xref(name:"Secunia", value:"32715");

  script_name(english:"Mozilla Thunderbird < 2.0.0.18 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");
  
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."  );
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is earlier than 2.0.0.18.  Such
versions are potentially affected by the following security issues :

  - The canvas element can be used in conjunction with an
    HTTP redirect to bypass same-origin restrictions and
    gain access to the content in arbitrary images from
    other domains. (MFSA 2008-48)

  - By tampering with the window.__proto__.__proto__ object,
    one can cause the browser to place a lock on a non-
    native object, leading to a crash and possible code
    execution. (MFSA 2008-50)

  - There are several stability bugs in the browser engine
    that could lead to crashes with evidence of memory
    corruption. (MFSA 2008-52)

  - Crashes and remote code execution in nsFrameManager are
    possible by modifying certain properties of a file
    input element before it has finished initializing.
    (MFSA 2008-55)

  - The same-origin check in
    'nsXMLHttpRequest::NotifyEventListeners()' can be
    bypassed. (MFSA 2008-56)

  - There is an error in the method used to parse the
    default namespace in an E4X document caused by quote
    characters in the namespace not being properly escaped.
    (MFSA 2008-58)

  - Scripts in a malicous mail message can access the
    .document URI and .textContext DOM properties.
    (MFSA 2008-59)"  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-48.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-50.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-52.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-55.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-56.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-58.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-59.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 2.0.0.18 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 94, 189, 200, 287, 399);
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/11/20");
  script_set_attribute(attribute:"patch_publication_date", value: "2008/11/12");
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

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'2.0.0.18', severity:SECURITY_HOLE);