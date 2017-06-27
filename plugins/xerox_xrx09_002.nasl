#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38790);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/11/05 20:37:10 $");

  script_cve_id("CVE-2009-1656");
  script_bugtraq_id(34984);
  script_osvdb_id(54457);
  script_xref(name:"Secunia", value:"35101");

  script_name(english:"Xerox WorkCentre Web Server Unspecified Command Injection (XRX09-002)");
  script_summary(english:"Checks Net Controller Software version of Xerox WorkCentre devices");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote multi-function device is affected by a command injection
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host
is a Xerox WorkCentre device that reportedly has an as-yet unspecified
command injection vulnerability in its web server.  A remote attacker
may be able to leverage this issue to execute arbitrary code via
carefully crafted inputs on an affected web page."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX09-02_v1.0.pdf");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the P38 patch as described in the Xerox security bulletin
referenced in the included URL."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:workcentre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");

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
  if (ssw && "." >< ssw) ssw = strstr(ssw, ".") - ".";
  ess = get_kb_item_or_exit("www/xerox_workcentre/ess");

  # No need to check further if ESS has ".P38" since that
  # indicates the patch has already been applied.
  if (ess && ess =~ "\.P38") audit(AUDIT_HOST_NOT, "affected");

  # Test model number and software version against those in Xerox's security bulletin.
  if (
    (
      # nb: models 232/238/245/255/265/275 with SSW in [*.27.24.000, *.60.22.050).
      model =~ "^(Pro )?2(3[28]|[4-7]5)($|[^0-9])" &&
      # nb: the leading part of the System SW has already been removed.
      ver_inrange(ver:ssw, low:"27.24.000", high:"60.22.049")
    ) ||
    (
      # nb: models 7655/7665/7675 with ESS in [040.032.000, 040.033.53110).
      model =~ "^76[5-7]5($|[^0-9])" &&
      ver_inrange(ver:ess, low:"040.032.0", high:"040.033.53109")
    ) ||
    (
      # nb: models 5632/5638/5645/5655/5665/5675/5687 with ESS in [050.060.50730, 050.060.50980].
      model =~ "^56(32|38|[4-7]5|87)($|[^0-9])" &&
      ver_inrange(ver:ess, low:"050.060.50730", high:"050.060.50980")
    )
  )
  security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
