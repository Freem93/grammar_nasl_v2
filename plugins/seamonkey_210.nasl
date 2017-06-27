#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59411);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id(
    "CVE-2012-0441",
    "CVE-2012-1937",
    "CVE-2012-1938",
    "CVE-2012-1940",
    "CVE-2012-1941",
    "CVE-2012-1942",
    "CVE-2012-1943",
    "CVE-2012-1944",
    "CVE-2012-1946",
    "CVE-2012-1947",
    "CVE-2012-1964"
 );
  script_bugtraq_id(
    53791,
    53792,
    53793,
    53794,
    53796,
    53798,
    53800,
    53801,
    53803,
    53807,
    54581
  );
  script_osvdb_id(
    82665,
    82667,
    82669,
    82670,
    82671,
    82672,
    82674,
    82675,
    82676,
    82677,
    84011
  );

  script_name(english:"SeaMonkey < 2.10.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of SeaMonkey is earlier than 2.10.0. Such
versions are potentially affected by the following security issues :

  - An error exists in the ASN.1 decoder when handling zero
    length items that can lead to application crashes.
    (CVE-2012-0441)

  - Multiple memory corruption errors exist. (CVE-2012-1937,
    CVE-2012-1938)

  - Two heap-based buffer overflows and one heap-based use-
    after-free error exist and are potentially exploitable.
    (CVE-2012-1940, CVE-2012-1941, CVE-2012-1947)

  - Two arbitrary DLL load issues exist related to the
    application update and update service functionality.
    (CVE-2012-1942, CVE-2012-1943)

  - The inline-script blocking feature of the 'Content
    Security Policy' (CSP) does not properly block inline
    event handlers. This error allows remote attackers to
    more easily carry out cross-site scripting attacks.
    (CVE-2012-1944)

  - A use-after-free error exists related to replacing or
    inserting a node into a web document. (CVE-2012-1946)

  - An error exists related to the certificate warning page
    that can allow 'clickjacking' thereby tricking a user
    into accepting unintended certificates. (CVE-2012-1964)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-34.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-35.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-36.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-38.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-39.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-40.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-54.html");

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to SeaMonkey 2.10.0 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.10.0', severity:SECURITY_HOLE, xss:TRUE);
