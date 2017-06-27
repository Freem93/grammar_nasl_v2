#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77283);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id(
    "CVE-2014-1533",
    "CVE-2014-1534",
    "CVE-2014-1536",
    "CVE-2014-1537",
    "CVE-2014-1538",
    "CVE-2014-1540",
    "CVE-2014-1541",
    "CVE-2014-1542",
    "CVE-2014-1543"
  );
  script_bugtraq_id(
    67969,
    67968,
    67979,
    67978,
    67966,
    67971,
    67976,
    67965,
    67964
  );
  script_osvdb_id(
    107907,
    107909,
    107910,
    107911,
    109409,
    109413,
    109414,
    109415,
    109416,
    109417,
    109419,
    109420,
    109421,
    109422,
    109423,
    109425,
    109426,
    109427,
    109429,
    109430,
    109431,
    109432,
    109433,
    109434,
    109435
  );

  script_name(english:"SeaMonkey < 2.26.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of SeaMonkey.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of SeaMonkey is a version prior to 2.26.1. It
is, therefore, affected by the following vulnerabilities :

  - There are multiple memory safety bugs in the browser
    engine. Several of these bugs show evidence of
    memory corruption, which may allow an attacker to
    execute arbitrary code. (CVE-2014-1533, CVE-2014-1534)

  - There are multiple use-after-free and out of bounds
    read issues. These issues have the potential to be
    exploited, resulting in remote code execution.
    (CVE-2014-1536, CVE-2014-1537, CVE-2014-1538)

  - A use-after-free error exists in the SMIL Animation
    Controller when interacting with and rendering
    improperly formed web content. This may result in a
    potentially exploitable crash. (CVE-2014-1541)

  - A use-after-free flaw exists in the event listener
    manager that can be triggered by web content. This may
    result in a potentially exploitable crash.
    (CVE-2014-1540)

  - A flaw exists in the Speex resample in Web Audio that
    results in a buffer overflow when working with audio
    content that exceeds the expected bounds. This flaw
    results in a potentially exploitable crash.
    (CVE-2014-1542)

  - There exists a buffer overflow in the Gamepad API when
    it is exercised with a gamepad device with
    non-contiguous axes. This flaw results in a potentially
    exploitable crash. (CVE-2014-1543)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-48.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-49.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-51.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-52.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-53.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-54.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.26.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.26.1', severity:SECURITY_HOLE, xss:FALSE);
