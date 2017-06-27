#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18642);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/11/05 20:35:00 $");

  script_cve_id("CVE-2005-2200", "CVE-2005-2201", "CVE-2005-2202");
  script_bugtraq_id(14187);
  script_osvdb_id(17765, 17766, 17768);

  script_name(english:"Xerox WorkCentre Multiple Vulnerabilities (XRX05-006)");
  script_summary(english:"Checks version of Xerox WorkCentre Pro");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer suffers from multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host
is a Xerox WorkCentre device with an embedded web server that suffers
from multiple flaws, including authentication bypass, denial of
service, unauthorized file access, and cross-site scripting."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX05_006.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX05_007.pdf");
  script_set_attribute(attribute:"solution", value:
"Apply the P22 patch as described in the Xerox security bulletins.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:workcentre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");

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

  # No need to check further if ESS has with ".P22" since that
  # indicates the patch has already been applied.
  if (ess && ess =~ "\.P22[^0-9]?") audit(AUDIT_HOST_NOT, "affected");

  # Test model number and software version against those in Xerox's security bulletin.
  if (
    # nb: models Pro 2128/2636/3545 Color with SSW 0.001.04.044 - 0.001.04.504.
    model =~ "Pro (32|40)C" && ver_inrange(ver:ssw, low:"0.001.04.044", high:"0.001.04.504")
  )
  security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
