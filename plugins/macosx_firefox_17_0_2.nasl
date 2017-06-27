#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63544);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/05/16 19:43:13 $");

  script_cve_id(
    "CVE-2013-0744",
    "CVE-2013-0745",
    "CVE-2013-0746",
    "CVE-2013-0747",
    "CVE-2013-0748",
    "CVE-2013-0750",
    "CVE-2013-0752",
    "CVE-2013-0753",
    "CVE-2013-0754",
    "CVE-2013-0755",
    "CVE-2013-0756",
    "CVE-2013-0757",
    "CVE-2013-0758",
    "CVE-2013-0759",
    "CVE-2013-0764",
    "CVE-2013-0768"
  );
  script_bugtraq_id(
    57204,
    57209,
    57211,
    57213,
    57215,
    57217,
    57218,
    57228,
    57232,
    57234,
    57235,
    57236,
    57238,
    57240,
    57241,
    57244,
    57258
  );
  script_osvdb_id(
    89008,
    89009,
    89010,
    89012,
    89013,
    89014,
    89015,
    89016,
    89017,
    89018,
    89019,
    89020,
    89021,
    89022,
    89023,
    89024
  );

  script_name(english:"Firefox ESR < 17.0.2 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox ESR is earlier than 17.0.2 and thus, 
is potentially affected by the following security issues :
    
  - Two intermediate certificates were improperly issued by
    TURKTRUST certificate authority. (CVE-2013-0743)

  - A use-after-free error exists related to displaying
    HTML tables with many columns and column groups.
    (CVE-2013-0744)

  - An error exists related to the 'AutoWrapperChanger'
    class that does not properly manage objects during
    garbage collection. (CVE-2012-0745)

  - An error exists related to 'jsval', 'quickstubs', and
    compartmental mismatches that could lead to potentially
    exploitable crashes. (CVE-2013-0746)

  - Errors exist related to events in the plugin handler
    that could allow same-origin policy bypass.
    (CVE-2013-0747)

  - An error related to the 'toString' method of XBL
    objects could lead to address information leakage.
    (CVE-2013-0748)

  - A buffer overflow exists related to JavaScript string
    concatenation. (CVE-2013-0750)
    
  - An error exists related to multiple XML bindings with
    SVG content, contained in XBL files. (CVE-2013-0752)

  - A use-after-free error exists related to
    'XMLSerializer' and 'serializeToStream'.
    (CVE-2013-0753)

  - A use-after-free error exists related to garbage
    collection and 'ListenManager'. (CVE-2013-0754)

  - A use-after-free error exists related to the 'Vibrate'
    library and 'domDoc'. (CVE-2013-0755)

  - A use-after-free error exists related to JavaScript
    'Proxy' objects. (CVE-2013-0756)
  
  - 'Chrome Object Wrappers' (COW) can be bypassed by
    changing object prototypes, which could allow 
    arbitrary code execution. (CVE-2013-0757)

  - An error related to SVG elements and plugins could 
    allow privilege escalation. (CVE-2013-0758)

  - An error exists related to the address bar that could
    allow URL spoofing attacks. (CVE-2013-0759)

  - An error exists related to SSL and threading that
    could result in potentially exploitable crashes.
    (CVE-2013-0764)

  - An error exists related to 'Canvas' and bad height or
    width values passed to it from HTML. (CVE-2013-0768)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-003/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-006/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-037/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-038/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-039/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-03/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-04/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-05/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-07/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-08/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-09/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-10/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-11/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-12/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-13/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-14/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-15/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-16/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-17/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-18/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-19/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2013-20/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 17.0.2 ESR or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 17.0.1 Flash Privileged Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");
kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

if (isnull(get_kb_item(kb_base + '/is_esr'))) audit(AUDIT_NOT_INST, 'Mozilla Firefox ESR');

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'17.0.2', severity:SECURITY_HOLE);