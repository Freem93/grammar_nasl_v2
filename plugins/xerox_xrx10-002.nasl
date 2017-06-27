#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44944);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/11/05 20:35:00 $");

  script_cve_id("CVE-2010-0548");
  script_bugtraq_id(37921);
   script_osvdb_id(61916, 61917);

  script_name(english:"Xerox WorkCentre Authorization Bypass Vulnerabilities (XRX10-002)");
  script_summary(english:"Checks Net Controller Software version of Xerox WorkCentre devices");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote multi-function device allows an attacker to gain access to
the device without authorization."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host
is a Xerox WorkCentre device that is affected by two authorization
bypass vulnerabilities :

  - The web interface reportedly includes a script named
    'YoUgoT_It.php' that will calculate a checksum for a
    specified folder name that will allow an attacker to
    access password-protected scan folders.

  - The web interface reportedly contains multiple scripts
    that fail to call 'die()' or 'exit()' after issuing a
    redirect to a login page when a visitor is not logged
    in and before running the rest of the script. It also
    contains scripts that are normally referenced within
    framesets that require credentials even though the
    scripts themselves do not when called directly."
  );
  # http://web.archive.org/web/20120612142911/https://www.sec-consult.com/files/20100208-0_xerox_backdoor_and_vuln.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eef14f03");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/509684/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX10-002_v1.0.pdf");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the P41v7 patch as described in the Xerox security bulletin
referenced above."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/01");

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
  if (ssw && "." >< ssw) ssw = strstr(ssw, ".") - ".";
  ess = get_kb_item_or_exit("www/xerox_workcentre/ess");

  # No need to check further if ESS has ".P41v7" since that
  # indicates the patch has already been applied.
  if (ess && ".P41v7" >< ess) audit(AUDIT_HOST_NOT, "affected");

  # Test model number and software version against those in Xerox's security bulletin.
  if (
    (
      # nb: models 5632/5638/5645/5655/5665/5675/5687 with ESS in one of the following ranges:
      #     [050.060.50730, 050.060.51010]
      #     [060.108.35300, 060.109.25900]
      #     [060.068.25600, 060.069.25900]
      model =~ "^56(32|38|[4-7]5|87)($|[^0-9])" &&
      (
        ver_inrange(ver:ess, low:"050.060.50730", high:"050.060.51010") ||
        ver_inrange(ver:ess, low:"060.108.35300", high:"060.109.25900") ||
        ver_inrange(ver:ess, low:"060.068.25600", high:"060.069.25900")
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
}
audit(AUDIT_HOST_NOT, "affected");
