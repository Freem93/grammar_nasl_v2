#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20951);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/23 20:52:20 $");

  script_cve_id(
    "CVE-2006-0825",
    "CVE-2006-0826",
    "CVE-2006-0827",
    "CVE-2006-0828"
  );
  script_bugtraq_id(16723, 16726, 16727);
  script_osvdb_id(23356, 23357, 23358, 23359);

  script_name(english:"Xerox WorkCentre Multiple Vulnerabilities (XRX06-001)");
  script_summary(english:"Checks software version in Xerox WorkCentre devices");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host
is a Xerox WorkCentre device that reportedly is affected by several
issues, including authentication bypass / unauthorized network access,
denial of service when handling malformed Postscript files, an
unspecified cross-site scripting issue, and unspecified errors that
might reduce the effectiveness of certain security features."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX06_001.pdf");
  script_set_attribute(
    attribute:"solution",
    value:
"Contact Xerox and request the solution for Security Bulletin Number
XRX06-001."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:workcentre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("xerox_workcentre_detect.nasl");
  script_require_keys("www/xerox_workcentre");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# This function returns TRUE if the version string ver lies in
# the range [low, high].
function ver_inrange(ver, low, high)
{
  local_var ver_parts, low_parts, high_parts, i, p, low_p, high_p;

  if (isnull(ver) || isnull(low) || isnull(high)) return FALSE;

  # Split levels into parts.
  ver_parts = split(ver, sep:".", keep:0);
  low_parts = split(low, sep:".", keep:0);
  high_parts = split(high, sep:".", keep:0);

  # Compare each part.
  i = 0;
  while (ver_parts[i] != NULL)
  {
    p = int(ver_parts[i]);
    low_p = int(low_parts[i]);
    if (low_p == NULL) low_p = 0;
    high_p = int(high_parts[i]);
    if (high_p == NULL) high_p = 0;

    if (p > low_p && p < high_p) return TRUE;
    if (p < low_p || p > high_p) return FALSE;
    ++i;
  }
  return TRUE;
}


# Check whether the device is vulnerable.
if (get_kb_item("www/xerox_workcentre"))
{
  model = get_kb_item_or_exit("www/xerox_workcentre/model");
  ssw = get_kb_item_or_exit("www/xerox_workcentre/ssw");

  # Test model number and software version against those in Xerox's security bulletin.
  if (
    # nb: models 232/238/245/255/265/275 with SSW < 14.027.24.015.
    (
      model =~ "2(32|38|45|55|65|75)" &&
      ver_inrange(ver:ssw, low:"0", high:"14.027.24.015")
    ) ||
    # nb: models 232/238/245/255/265/275 with SSW < 14.027.24.015.
    (
      model =~ "Pro 2(32|38|45|55|65|75)" &&
      ver_inrange(ver:ssw, low:"0", high:"13.027.24.015")
    )
  )
  security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
