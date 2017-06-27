#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40807);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/11/05 20:39:26 $");

  script_bugtraq_id(36177);
  script_osvdb_id(57569);

  script_name(english:"Xerox WorkCentre Web Services Extensible Interface Platform Unauthorized Access (XRX09-003)");
  script_summary(english:"Checks Net Controller Software version of Xerox WorkCentre devices");

  script_set_attribute(attribute:"synopsis", value:
"The remote multi-function device may allow unauthorized access.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host
is a Xerox WorkCentre device that could allow a remote attacker to
obtain unauthorized access to device configuration settings, possibly
exposing customer passwords.

Note that successful exploitation requires that SSL is not enabled for
the web server component."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX09-003_v1.3.pdf");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the P39 patch as described in the Xerox security bulletin
referenced above."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/28");

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

  # No need to check further if ESS has ".P39v5" since that
  # indicates the patch has already been applied.
  if (ess && ".P39v5" >< ess) audit(AUDIT_HOST_NOT, "affected");

  # Test model number and software version against those in Xerox's security bulletin.
  if (
    (
      # nb: models 5030/5050 with ESS starting with 001.035.547.01.
      model =~ "^50[35]0($|[^0-9])" &&
      ver_inrange(ver:ess, low:"001.035.547.01", high:"001.035.547.01")
    ) ||
    (
      # nb: model 6400 with ESS starting with 060.079.11410.
      model =~ "^6400($|[^0-9])" &&
      ver_inrange(ver:ess, low:"060.079.11410", high:"060.079.11410")
    ) ||
    (
      # nb: models 7655/7665/7675 with ESS in the following ranges:
      #    [040.032, 040.032]
      #    [040.033.50500, 040.033.53040]
      #    [040.033.53050, 040.033.53130]
      model =~ "^76[567]5($|[^0-9])" &&
      (
        ver_inrange(ver:ess, low:"040.032", high:"040.032") ||
        ver_inrange(ver:ess, low:"040.033.50500", high:"040.033.53040") ||
        ver_inrange(ver:ess, low:"040.033.53050", high:"040.033.53130")
      )
    ) ||
    (
      # nb: models CQ 9201/9202/9203 with ESS in the range [060.059.07210, 060.059.16420]
      model =~ "^CQ 920[123]($|[^0-9])" &&
      ver_inrange(ver:ess, low:"060.059.07210", high:"060.059.16420")
    ) ||
    (
      # nb: models 5632/5638/5645/5655/5665/5675/5687 with ESS in one of the following ranges:
      #     [050.060.50730, 050.060.51000]
      #     [060.108.35300, 060.109.10507]
      #     [060.068.25600, 060.069.10508]
      model =~ "^56(32|38|[4-7]5|87)($|[^0-9])" &&
      (
        ver_inrange(ver:ess, low:"050.060.50730", high:"050.060.51000") ||
        ver_inrange(ver:ess, low:"060.108.35300", high:"060.109.10507") ||
        ver_inrange(ver:ess, low:"060.068.25600", high:"060.069.10508")
      )
    ) ||
    (
      # nb: models 5135/5150 with ESS starting with 060.109.10507
      model =~ "^51(35|50)($|[^0-9])" &&
      ver_inrange(ver:ess, low:"060.109.10507", high:"060.109.10507")
    )
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Model : ' + model +
        '\n  ESS Controller version : ' + ess + '\n';
      security_warning(port:0, extra:report);
    }
    else security_warning(0);
    exit(0);
  }
}
audit(AUDIT_HOST_NOT, "affected");
