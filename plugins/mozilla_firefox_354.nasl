#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");


if (description)
{
  script_id(42306);
  script_version("$Revision: 1.21 $");

  script_cve_id(
    "CVE-2009-0689",
    # "CVE-2009-3274",    # applies to Linux only.
    "CVE-2009-3370",
    "CVE-2009-3371",
    "CVE-2009-3372",
    "CVE-2009-3373",
    "CVE-2009-3374",
    "CVE-2009-3375",
    "CVE-2009-3376",
    "CVE-2009-3377",
    "CVE-2009-3378",
    "CVE-2009-3379",
    "CVE-2009-3380",
    "CVE-2009-3381",
    "CVE-2009-3382",
    "CVE-2009-3383"
  );
  script_bugtraq_id(
    36851,
    # 36852,    # applies to Linux only.
    36853,
    36854,
    36855,
    36856,
    36857,
    36858,
    36866,
    36867,
    36869,
    36870,
    36871,
    36872,
    36873,
    36875
  );
  script_osvdb_id(
    55603,
    59381,
    59382,
    59383,
    59384,
    59385,
    59386,
    59388,
    59389,
    59390,
    59391,
    59392,
    59393,
    59394,
    59395,
    61091
  );
  script_xref(name:"Secunia", value:"36649");
  script_xref(name:"Secunia", value:"36711");

  script_name(english:"Firefox 3.5.x < 3.5.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute( attribute:"synopsis",  value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities."  );
  script_set_attribute( attribute:"description",  value:
"The installed version of Firefox 3.5 is earlier than 3.5.4.  Such
versions are potentially affected by the following security issues :

  - It may be possible for a malicious web page to
    steal form history. (MFSA 2009-52)

  - By predicting the filename of an already 
    downloaded file in the downloads directory, a
    local attacker may be able to trick the browser
    into opening an incorrect file. (MFSA 2009-53)

  - Recursive creation of JavaScript web-workers 
    could crash the browser or allow execution of 
    arbitrary code on the remote system.
    (MFSA 2009-54)

  - Provided the browser is configured to use Proxy
    Auto-configuration it may be possible for an 
    attacker to crash the browser or execute 
    arbitrary code. (MFSA 2009-55)

  - Mozilla's GIF image parser is affected by a 
    heap-based buffer overflow. (MFSA 2009-56)

  - A vulnerability in XPCOM utility 
    'XPCVariant::VariantDataToJS' could allow 
    executing arbitrary JavaScript code with chrome
    privileges. (MFSA 2009-57)

  - A vulnerability in Mozilla's string to floating
    point number conversion routine could allow 
    arbitrary code execution on the remote system. 
    (MFSA 2009-59)

  - It may be possible to read text from a web page 
    using JavaScript function 'document.getSelection()
    from a different domain. (MFSA 2009-61)

  - If a file contains right-to-left override 
    character (RTL) in the filename it may be possible
    for an attacker to obfuscate the filename and 
    extension of the file being downloaded. 
    (MFSA 2009-62)

  - Multiple memory safety bugs in media libraries
    could potentially allow arbitrary code execution.
    (MFSA 2009-63)

  - Multiple memory corruption vulnerabilities could
    potentially allow arbitrary code execution.
    (MFSA 2009-64)"  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-52.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-53.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-54.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-55.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-56.html"
  );
  script_set_attribute( 
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-57.html"
  );  
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-59.html"
  );  
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-61.html"
  );  
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-62.html"
  );  
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-63.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-64.html"
  );  

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Firefox 3.5.4 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 119, 264, 399);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/10/27"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/10/27"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/29"
  );
 script_cvs_date("$Date: 2016/12/05 14:32:01 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.5.4', min:'3.5', severity:SECURITY_HOLE);