#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83439);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/06/15 16:38:32 $");

  script_cve_id(
    "CVE-2011-3079",
    "CVE-2015-0833",
    "CVE-2015-2708",
    "CVE-2015-2709",
    "CVE-2015-2710",
    "CVE-2015-2711",
    "CVE-2015-2712",
    "CVE-2015-2713",
    "CVE-2015-2715",
    "CVE-2015-2716",
    "CVE-2015-2717",
    "CVE-2015-2718",
    "CVE-2015-2720",
    "CVE-2015-4496"
  );
  script_bugtraq_id(
    53309,
    72747,
    74611,
    74615,
    76333
  );
  script_osvdb_id(
    81645,
    118692,
    118692,
    122020,
    122021,
    122022,
    122023,
    122024,
    122025,
    122026,
    122027,
    122028,
    122029,
    122030,
    122031,
    122032,
    122033,
    122034,
    122035,
    122036,
    122038,
    122039,
    122040,
    122041,
    126095
  );

  script_name(english:"Firefox < 38.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior
to 38.0. It is, therefore, affected by the following vulnerabilities :

  - A privilege escalation vulnerability exists in the
    Inter-process Communications (IPC) implementation due
    to a failure to validate the identity of a listener
    process. (CVE-2011-3079)

  - An issue exists in the Mozilla updater in which DLL
    files in the current working directory or Windows
    temporary directories will be loaded, allowing the
    execution of arbitrary code. (CVE-2015-0833 /
    CVE-2015-2720)

  - Multiple memory corruption issues exist within the
    browser engine. A remote attacker can exploit these to
    corrupt memory and execute arbitrary code.
    (CVE-2015-2708, CVE-2015-2709)

  - A buffer overflow condition exists in SVGTextFrame.cpp
    when rendering SVG graphics that are combined with
    certain CSS properties due to improper validation of
    user-supplied input. A remote attacker can exploit this
    to cause a heap-based buffer overflow, resulting in the
    execution of arbitrary code. (CVE-2015-2710)
    
  - A security bypass vulnerability exists due to the
    referrer policy not being enforced in certain situations
    when opening links (e.g. using the context menu or a
    middle-clicks by mouse). A remote attacker can exploit
    this to bypass intended policy settings. (CVE-2015-2711)
    
  - An out-of-bounds read and write issue exists in the
    CheckHeapLengthCondition() function due to improper
    JavaScript validation of heap lengths. A remote attacker
    can exploit this, via a specially crafted web page, to
    disclose memory contents. (CVE-2015-2712)

  - A use-after-free error exists due to improper processing
    of text when vertical text is enabled. A remote attacker
    can exploit this to dereference already freed memory.
    (CVE-2015-2713)

  - A use-after-free error exists in the
    RegisterCurrentThread() function in nsThreadManager.cpp
    due to a race condition related to media decoder threads
    created during the shutdown process. A remote attacker
    can exploit this to dereference already freed memory.
    (CVE-2015-2715)

  - A buffer overflow condition exists in the
    XML_GetBuffer() function in xmlparse.c due to improper
    validation of user-supplied input when handling
    compressed XML content. An attacker can exploit this to
    cause a buffer overflow, resulting in the execution of
    arbitrary code. (CVE-2015-2716)

  - An integer overflow condition exists in the parseChunk()
    function in MPEG4Extractor.cpp due to improper handling
    of MP4 video metadata in chunks. A remote attacker can
    exploit this, via specially crafted media content, to
    cause a heap-based buffer overflow, resulting in the
    execution of arbitrary code. (CVE-2015-2717)

  - A security bypass vulnerability exists in WebChannel.jsm
    due to improper handling of message traffic. An
    untrusted page hosting a trusted page within an iframe
    can intercept webchannel responses for the trusted page.
    This allows a remote attacker, via a specially crafted
    web page, to bypass origin restrictions, resulting in
    the disclosure of sensitive information. (CVE-2015-2718)

  - Multiple integer overflow conditions exist in the
    bundled libstagefright component due to improper
    validation of user-supplied input when processing MPEG4
    sample metadata. A remote attacker can exploit this, via
    specially crafted media content, to execute arbitrary
    code. (CVE-2015-4496)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-46/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-48/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-49/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-50/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-51/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-53/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-54/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-55/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-56/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-57/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-58/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-93/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 38.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'38.0', severity:SECURITY_HOLE);
