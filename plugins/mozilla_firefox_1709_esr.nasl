#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69992);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/10/15 20:31:39 $");

  script_cve_id(
    "CVE-2013-1718",
    "CVE-2013-1719",
    "CVE-2013-1725",
    "CVE-2013-1730",
    "CVE-2013-1732",
    "CVE-2013-1735",
    "CVE-2013-1736",
    "CVE-2013-1737"
  );
  script_bugtraq_id(
    62462,
    62463,
    62467,
    62469,
    62473,
    62475,
    62478,
    62479
  );
  script_osvdb_id(
    97388,
    97389,
    97390,
    97391,
    97392,
    97398,
    97403,
    97404
  );

  script_name(english:"Firefox ESR 17.x < 17.0.9 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser that is potentially
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox ESR 17.x is earlier than 17.0.9, and
is, therefore, potentially affected by the following vulnerabilities :

  - Memory issues exist in the browser engine that could
    allow for denial of service or arbitrary code execution.
    (CVE-2013-1718, CVE-2013-1719)

  - Multiple use-after-free problems exist that could result
    in denial of service attacks or arbitrary code
    execution. (CVE-2013-1735, CVE-2013-1736)

  - A buffer overflow is possible because of an issue with
    multi-column layouts. (CVE-2013-1732)

  - A JavaScript compartment mismatch could result in a
    denial of service or arbitrary code execution.
    Versions of Firefox 20 or greater are not susceptible to
    the arbitrary code execution mentioned above.
    (CVE-2013-1730)

  - Incorrect scope handling for JavaScript objects with
    compartments could result in denial of service or
    possibly arbitrary code execution. (CVE-2013-1725)

  - An object is not properly identified during use of
    user-defined getter methods on DOM proxies.  This could
    result in access restrictions being bypassed.
    (CVE-2013-1737)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-76.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-82.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-88.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-89.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-90.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-91.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 17.0.9 ESR or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'17.0.9', min:'17.0', severity:SECURITY_HOLE, xss:FALSE);
