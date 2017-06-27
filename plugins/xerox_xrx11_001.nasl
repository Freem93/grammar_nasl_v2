#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51901);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/11/05 20:35:00 $");

  script_bugtraq_id(46160);
  script_osvdb_id(70807);

  script_name(english:"Xerox WorkCentre Command Injection (XRX11-001)");
  script_summary(english:"Checks Net Controller Software version of Xerox WorkCentre devices");

  script_set_attribute(attribute:"synopsis", value:
"The remote multi-function device may allow arbitrary code execution.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host
is a Xerox WorkCentre device that reportedly allows an unauthenticated
attacker to execute arbitrary code via specially crafted HTTP requests."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX11-001_v1.0.pdf");
  script_set_attribute(attribute:"solution", value:
"Apply the P45 patch as described in the Xerox security bulletin.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:workcentre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("xerox_workcentre_detect.nasl");
  script_require_keys("www/xerox_workcentre", "www/xerox_workcentre/model", "www/xerox_workcentre/ess");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("www/xerox_workcentre");
model = get_kb_item_or_exit("www/xerox_workcentre/model");
ess = get_kb_item_or_exit("www/xerox_workcentre/ess");


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


# No need to check if ESS has ".P45v2" since that
# indicates the patch has already been applied.
if (".P45v2" >< ess) audit(AUDIT_HOST_NOT, "affected");


# Test model number and software version against those in Xerox's security bulletin.
if (
  (
    # nb: models 7655/7665/7675 with ESS in the following ranges:
    #    [040.032, 040.032]
    #    [040.033.50500, 040.033.53040]
    #    [040.033.53050, 040.033.53210]
    model =~ "^76[567]5($|[^0-9])" &&
    (
      ver_inrange(ver:ess, low:"040.032.0",     high:"040.032.99999") ||
      ver_inrange(ver:ess, low:"040.033.50500", high:"040.033.53040") ||
      ver_inrange(ver:ess, low:"040.033.53050", high:"040.033.53210")
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model : ' + model +
      '\n  ESS Controller version : ' + ess + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
