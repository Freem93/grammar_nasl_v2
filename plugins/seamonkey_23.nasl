#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55885);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/09/25 12:35:45 $");

  script_cve_id(
    "CVE-2011-0084",
    "CVE-2011-2985",
    "CVE-2011-2986",
    "CVE-2011-2987",
    "CVE-2011-2988",
    "CVE-2011-2989",
    "CVE-2011-2990",
    "CVE-2011-2991",
    "CVE-2011-2992",
    "CVE-2011-2993",
    "CVE-2011-2999"
  );
  script_bugtraq_id(
    49213,
    49224,
    49226,
    49227,
    49239,
    49242,
    49243,
    49245,
    49246,
    49248,
    49848
  );
  script_osvdb_id(
    74581,
    74588,
    74589,
    74590,
    74591,
    74592,
    74593,
    74594,
    74595,
    74596,
    75838
  );

  script_name(english:"SeaMonkey < 2.3.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The installed version of SeaMonkey is earlier than 2.3.0. Such
versions are potentially affected by the following security issues :

  - An error in SVG text manipulation code creates a
    dangling pointer vulnerability. (CVE-2011-0084)

  - Multiple, unspecified memory safety issues exist.
    (CVE-2011-2985)

  - An error in the D2D hardware acceleration code can allow
    image data from one domain to be read by another domain.
    (CVE-2011-2986)

  - An error in the ANGLE library used by the WebGL
    implementation can allow heap overflows, possibly
    leading to code execution. (CVE-2011-2987)

  - An error in the shader program handling code can allow
    a large shader program to overflow a buffer and crash.
    (CVE-2011-2988)

  - An unspecified error exists related to WebGL. 
    (CVE-2011-2989)

  - Two errors exist related to Content Security Policy
    and can lead to information disclosure. (CVE-2011-2990)

  - An unspecified error exists that can allow JavaScript
    crashes. (CVE-2011-2991)

  - An unspecified error exists that can allow the Ogg 
    reader to crash. (CVE-2011-2992)

  - An unspecified error exists that can allow unsigned
    JavaScript to call into a signed JAR and inherit the
    signed JAR's permissions and identity. (CVE-2011-2993)

  - There is an error in the implementation of the
    'window.location' JavaScript object when creating named
    frames. This can be exploited to bypass the same-origin
    policy and potentially conduct cross-site scripting
    attacks.(CVE-2011-2999)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-33.html");
  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-38.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.3.0', severity:SECURITY_HOLE);