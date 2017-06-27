#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18206);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/08/08 14:24:01 $");

  script_cve_id("CVE-2005-0703", "CVE-2005-1179");
  script_bugtraq_id(12731, 13196, 13198);
  script_osvdb_id(14579, 15747);

  script_name(english:"Xerox WorkCentre MicroServer Multiple Vulnerabilities (XRX05-005)");
  script_summary(english:"Checks version of Xerox device");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote printer suffers from multiple unauthorized access
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host
is a Xerox WorkCentre device with an embedded web server with an
unauthenticated account and a weakness in its SNMP authentication.
These flaws could allow a remote attacker to bypass authentication and
change the device's configuration."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX05_005.pdf");
  script_set_attribute(attribute:"solution", value:"Apply the P21 patch as described in the Xerox security bulletin.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:workcentre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

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
  ess = get_kb_item_or_exit("www/xerox_workcentre/ess");

  # No need to check further if ESS has with ".P21" since that
  # indicates the patch has already been applied (except for
  # WorkCentre M35/M45/M55 and M165/M175).
  if (ess && ess =~ "\.P21[^0-9]?") audit(AUDIT_HOST_NOT, "affected");

  # Test model number and software version against those in Xerox's security bulletin.
  if (
    # nb: models M35/M45/M55 with SSW 2.028.11.000 - 2.97.20.032 or 4.84.16.000 - 4.97.20.032.
    (
      model =~ "M[345]5" &&
      (
        ver_inrange(ver:ssw, low:"2.028.11.000", high:"2.97.20.032") ||
        ver_inrange(ver:ssw, low:"4.84.16.000", high:"4.97.20.032")
      )
    ) ||

    # nb: models Pro 35/45/55 with SSW 3.028.11.000 - 3.97.20.032.
    (model =~ "Pro [345]5" && ver_inrange(ver:ssw, low:"3.028.11.000", high:"3.97.20.032")) ||

    # nb: models Pro 65/75/90 with SSW 1.001.00.060 - 1.001.02.084.
    (model =~ "Pro (65|75|90)" && ver_inrange(ver:ssw, low:"1.001.00.060", high:"1.001.02.084")) ||

    # nb: models Pro 32/40 Color with SSW 0.001.00.060 - 0.001.02.081.
    (model =~ "Pro (32|40)C" && ver_inrange(ver:ssw, low:"0.001.00.060", high:"0.001.02.081")) ||

    # nb: models M165/M175 with SSW 6.47.30.000 - 6.47.33.008 or 8.47.30.000 - 8.47.33.008
    (
      model =~ "M1[67]5" &&
      (
        ver_inrange(ver:ssw, low:"6.47.30.000", high:"6.47.33.008") ||
        ver_inrange(ver:ssw, low:"8.47.30.000", high:"8.47.33.008")
      )
    ) ||

    # nb: models Pro 165/175 with SSW 7.47.30.000 - 7.47.33.008.
    (model =~ "Pro 1[67]5" && ver_inrange(ver:ssw, low:"7.47.30.000", high:"7.47.33.008")) ||

    # nb: models Pro Color 2128/2636/3545 with SSW 0.001.04.044.
    (model =~ "Pro (2128|2636|3545)C" && ver_inrange(ver:ssw, low:"0.001.04.044", high:"0.001.04.044"))
  )
  security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
