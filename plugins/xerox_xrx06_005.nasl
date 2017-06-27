#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22498);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/11/05 20:37:10 $");

  script_cve_id("CVE-2006-5290");
  script_bugtraq_id(20334);
  script_osvdb_id(29507);

  script_name(english:"Xerox WorkCentre WebUI Arbitrary Command Execution (XRX06-005)");
  script_summary(english:"Checks Net Controller Software version of Xerox WorkCentre devices");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote multi-function device is prone to a code injection
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host
is a Xerox WorkCentre device that is reportedly prone to a code
injection issue that could allow execution of arbitrary code on the
remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX06_005.pdf");
  script_set_attribute(attribute:"solution", value:
"Apply the P29 patch as described in the Xerox security bulletins.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/05");

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
  ess = get_kb_item_or_exit("www/xerox_workcentre/ess");

  # No need to check further if ESS has ".P29" since that
  # indicates the patch has already been applied.
  if (ess && ess =~ "\.P29") audit(AUDIT_HOST_NOT, "affected");

  # Test model number and software version against those in Xerox's security bulletin.
  if (
    # nb: models 232/238/245/255/265/275 with ESS in [040.010.0930, 040.010.2280).
    (model =~ "^2(3[28]|[4-7]5)" || model =~ "Pro 2(3[28]|[4-7]5)") &&
    ver_inrange(ver:ess, low:"040.010.0930", high:"040.010.2279")
  )
  security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
