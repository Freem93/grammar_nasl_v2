#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56751);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/09/17 11:05:43 $");

  script_cve_id(
    "CVE-2011-3648",
    "CVE-2011-3649",
    "CVE-2011-3650",
    "CVE-2011-3651",
    "CVE-2011-3652",
    "CVE-2011-3653",
    "CVE-2011-3654",
    "CVE-2011-3655"
  );
  script_bugtraq_id(
    50591, 
    50592, 
    50593, 
    50594, 
    50595, 
    50597, 
    50600, 
    50602
  );
  script_osvdb_id(76948, 76949, 76950, 76951, 76952, 76953, 76954, 76955);

  script_name(english:"Firefox < 8.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 8.0 and thus, is
potentially affected by the following security issues :

  - Certain invalid sequences are not handled properly in
    'Shift-JIS' encoding and can allow cross-site scripting
    attacks. (CVE-2011-3648)

  - The addition of the 'Azure' graphics functionality re-
    introduced a cross-origin information disclosure issue
    previously described in CVE-2011-2986. (CVE-2011-3649)

  - Profiling JavaScript files with many functions can cause
    the application to crash. It may be possible to trigger
    this behavior even when the debugging APIs are not being
    used. (CVE-2011-3650)

  - Multiple memory safety issues exist. (CVE-2011-3651)

  - An unchecked memory allocation failure can cause the
    application to crash. (CVE-2011-3652)

  - An issue with WebGL graphics and GPU drivers can allow
    cross-origin image theft. (CVE-2011-3653)

  - An error exists related to SVG 'mpath' linking to a
    non-SVG element and can result in potentially
    exploitable application crashes. (CVE-2011-3654)

  - An error in internal privilege checking can allow
    web content to obtain elevated privileges.
    (CVE-2011-3655)");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-47.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-48.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-49.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-50.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-51.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-52.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'8.0', skippat:'^3\\.6\\.', severity:SECURITY_HOLE);