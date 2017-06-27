#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21027);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/11/05 20:35:00 $");

  script_cve_id("CVE-2006-1136", "CVE-2006-1137", "CVE-2006-1138");
  script_bugtraq_id(17014);
  script_osvdb_id(23724, 23725, 23726, 23727);

  script_name(english:"Xerox WorkCentre Multiple Vulnerabilities (XRX06-002)");
  script_summary(english:"Checks version of Xerox WorkCentre devices");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host
is a Xerox WorkCentre device that reportedly is affected by several
issues, including several denial of service issues."
  );
  # http://a1851.g.akamaitech.net/f/1851/2996/24h/cacheB.xerox.com/downloads/gbr/en/c/cert_XRX06_002v12.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5133ae4b");
  script_set_attribute(
    attribute:"solution",
    value:
"Contact Xerox and request either system software version 1.001.02.074
/ 1.001.02.716 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:workcentre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

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
    # nb: models 65/75/90 with SSW <= 1.001.02.073 or (1.001.02.074, 1.001.02.715).
    (
      model =~ "Pro (65|75|90)" &&
      (
        ver_inrange(ver:ssw, low:"0", high:"1.001.02.073") ||
        # nb: ranges for ver_inrange() are inclusive.
        ver_inrange(ver:ssw, low:"1.001.02.075", high:"1.001.02.714")
      )
    )
  )
  security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
