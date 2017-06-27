#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44943);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/11/05 20:39:26 $");

  script_cve_id("CVE-2010-0549");
  script_osvdb_id(61925);

  script_name(english:"Xerox WorkCentre Crafted PostScript File Handling Directory Access (XRX10-001)");
  script_summary(english:"Checks Net Controller Software version of Xerox WorkCentre devices");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote multi-function device allows an attacker to gain access to
the Network Controller directory structure without authorization."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host
is a Xerox WorkCentre device that could allow unauthorized access to
the Network Controller directory structure using a specially crafted
PostScript file.

A remote attacker may be able to leverage this to gain access to
sensitive information from the affected device."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX10-001_v1.0.pdf");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the P40v1 patch as described in the Xerox security bulletin
referenced above."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/22");
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

  # No need to check further if ESS has ".P40v1" since that
  # indicates the patch has already been applied.
  if (ess && ".P40v1" >< ess) audit(AUDIT_HOST_NOT, "affected");

  # Test model number and software version against those in Xerox's security bulletin.
  if (
    # nb: model 6400 [060.079.11410, 060.079.29310]
    model =~ "^6400($|[^0-9])" &&
    ver_inrange(ver:ess, low:"060.079.11410", high:"060.079.29310")
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
