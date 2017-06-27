#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47106);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/11/05 20:37:10 $");

  script_bugtraq_id(40946);

  script_name(english:"Xerox WorkCentre Multiple Unspecified Vulnerabilities (XRX10-003)");
  script_summary(english:"Checks Net Controller Software version of Xerox WorkCentre devices");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote multi-function device is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host
is a Xerox WorkCentre device that is affected by multiple and as-yet
unspecified vulnerabilities."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX10-003_v1.0.pdf");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the appropriate cumulative update as described in the Xerox
security bulletin referenced above."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:workcentre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");

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
  # nb: this time I want the full System Software version.
  # if (ssw && "." >< ssw) ssw = strstr(ssw, ".") - ".";
  ess = get_kb_item_or_exit("www/xerox_workcentre/ess");

  # nb: Per the advisory, "The WC 5632-5687 models that use System
  #     Software Version 21.113.02.000 with the P33 patch installed
  #     are Common Criteria Certified, thus are not applicable to
  #     this bulletin." While this SSW value is not included in the
  #     initial ranges below, let's make sure we never fire on it.
  if (
    model =~ "^56(32|38|[4-7]5|87)($|[^0-9])" &&
    ssw == "21.113.02.000" &&
    ".P33" >< ess
  ) exit(0, "The host is Common Criteria Certified and thus not applicable to XRX10-003.");

  # Test model number and software version against those in Xerox's security bulletin.
  if (
    (
      # nb: models 5632/5638/5645/5655/5665/5675/5687 with System SW in one of the following ranges:
      #     Multi-Board Controller (MBC) products
      #       [021.120.031.00000, 021.120.032.00000]
      #       [021.120.038.00000, 021.120.039.00000]
      #       [021.120.045.00045, 021.120.052.00000]
      #     Single Board Controller (SBC) products
      #       [025.054.010.00000, 025.054.033.00000]
      #       [025.054.010.0005, 025.054.010.0005]
      #       [025.054.010.0006, 025.054.039.000]
      #       [025.054.040.00050, 025.054.053.00000]
      model =~ "^56(32|38|[4-7]5|87)($|[^0-9])" &&
      (
        ver_inrange(ver:ssw, low:"021.120.031.00000", high:"021.120.032.00000") ||
        ver_inrange(ver:ssw, low:"021.120.038.00000", high:"021.120.039.00000") ||
        ver_inrange(ver:ssw, low:"021.120.045.00045", high:"021.120.045.00045") ||
        ver_inrange(ver:ssw, low:"025.054.010.00000", high:"025.054.033.00000") ||
        ver_inrange(ver:ssw, low:"025.054.010.0005",  high:"025.054.010.0005") ||
        ver_inrange(ver:ssw, low:"025.054.010.0006",  high:"025.054.039.000") ||
        ver_inrange(ver:ssw, low:"025.054.040.00050", high:"025.054.053.00000")
      )
    ) ||
    (
      # nb: models 5135/5150 with System SW in one of the following ranges:
      #     [021.120.039.00000, 021.120.039.00000]
      #     [021.120.045.00045, 021.120.052.00000]
      model =~ "^51(3550)($|[^0-9])" &&
      (
        ver_inrange(ver:ssw, low:"021.120.039.00000", high:"021.120.039.00000") ||
        ver_inrange(ver:ssw, low:"021.120.045.00045", high:"021.120.052.00000")
      )
    )
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Model                   : ' + model +
        '\n  ESS Controller version  : ' + ess +
        '\n  System Software version : ' + ssw + '\n';
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
    exit(0);
  }
}
audit(AUDIT_HOST_NOT, "affected");
