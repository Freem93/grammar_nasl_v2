#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65809);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/01 11:06:37 $");

  script_cve_id(
    "CVE-2013-0788",
    "CVE-2013-0789",
    "CVE-2013-0791",
    "CVE-2013-0792",
    "CVE-2013-0793",
    "CVE-2013-0794",
    "CVE-2013-0795",
    "CVE-2013-0797",
    "CVE-2013-0800"
  );
  script_bugtraq_id(
    58819,
    58821,
    58825,
    58826,
    58827,
    58828,
    58835,
    58836,
    58837
  );
  script_osvdb_id(
    91874,
    91875,
    91878,
    91880,
    91881,
    91882,
    91883,
    91885,
    91886
  );

  script_name(english:"SeaMonkey < 2.17 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser that is potentially
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of SeaMonkey is earlier than 2.17 and thus, is
potentially affected by the following vulnerabilities :

  - Various memory safety issues exist. (CVE-2013-0788,
    CVE-2013-0789)

  - An out-of-bounds memory read error exists related to
    'CERT_DecodeCertPackage' and certificate decoding.
    (CVE-2013-0791)

  - A memory corruption error exists related to PNG image
    files when 'gfx.color_management.enablev4' is manually
    enabled in the application's configuration.
    (CVE-2013-0792)

  - An error exists related to navigation, history and
    improper 'baseURI' property values that could allow
    cross-site scripting attacks. (CVE-2013-0793)

  - An error exists related to tab-modal dialog boxes that
    could be used in phishing attacks. (CVE-2013-0794)

  - An error exists related to 'cloneNode' that can allow
    'System Only Wrapper' (SOW) to be bypassed, thus
    violating the same origin policy and possibly leading
    to privilege escalation and code execution.
    (CVE-2013-0795)

  - A DLL loading vulnerability exists that could lead to
    code execution. (CVE-2013-0797)

  - An out-of-bounds write error exists related to the
    Cairo graphics library. (CVE-2013-0800)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-30.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-31.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-34.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-36.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-37.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-38.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-39.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-40.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.17', severity:SECURITY_HOLE);
