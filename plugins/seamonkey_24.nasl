#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56337);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id(
    "CVE-2011-2372",
    "CVE-2011-2995",
    "CVE-2011-2997",
    "CVE-2011-3000",
    "CVE-2011-3001",
    "CVE-2011-3002",
    "CVE-2011-3003",
    "CVE-2011-3004",
    "CVE-2011-3005",
    "CVE-2011-3232"
  );
  script_bugtraq_id(
    49800,
    49808,
    49811,
    49813,
    49837,
    49847,
    49849,
    49850,
    49852
  );
  script_osvdb_id(
    75834,
    75836,
    75839,
    75840,
    75841,
    75842,
    75843,
    75844,
    75845,
    75846,
    75847
  );

  script_name(english:"SeaMonkey < 2.4.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The installed version of SeaMonkey is earlier than 2.4.0. Such
versions are potentially affected by the following security issues :

  - If an attacker could trick a user into holding down the
    'Enter' key, via a malicious game, for example, a
    malicious application or extension could be downloaded
    and executed.(CVE-2011-2372, CVE-2011-3001)

  - Unspecified errors exist that can be exploited to
    corrupt memory. No additional information is available
    at this time. (CVE-2011-2995, CVE-2011-2997)

  - A weakness exists when handling the 'Location' header.
    This can lead to response splitting attacks when
    visiting a vulnerable web server. The same fix has been
    applied to the headers 'Content-Length' and
    'Content-Disposition'. (CVE-2011-3000)

  - An error exists within WebGL's ANGLE library. It does
    not properly check for return values from the
    'GrowAtomTable()' function. This vulnerability can be
    exploited to cause a buffer overflow by sending a
    series of requests. Additionally, an unspecified error
    exists within WebGL that can be exploited to corrupt
    memory. (CVE-2011-3002, CVE-2011-3003)

  - There is an error within the JSSubScriptLoader that
    incorrectly unwraps 'XPCNativeWrappers'. By tricking
    a user into installing a malicious plug-in, an attacker
    could exploit this issue to execute arbitrary code.
    (CVE-2011-3004)

  - A use-after-free error exists when parsing OGG headers.
    (CVE-2011-3005)

  - There is an unspecified error within the YARR regular
    expression library that can be exploited to corrupt
    memory. (CVE-2011-3232)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-36.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-39.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-40.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-41.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-42.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-43.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-44.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-45.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.4.0', severity:SECURITY_HOLE);