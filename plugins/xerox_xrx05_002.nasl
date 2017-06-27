#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18267);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/11/05 20:37:10 $");

  script_bugtraq_id(12787);
  script_osvdb_id(53643);

  script_name(english:"Xerox WorkCentre Multi-Page Document Scan/Fax Information Disclosure (XRX05-002)");
  script_summary(english:"Checks version of Xerox WorkCentre device");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote printer is affected by an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host
is a Xerox WorkCentre device that may, under rare conditions, send a
fax or scan to a different addressee than intended.  This occurs only
when faxing (not copying) a multi-page document and a power failure
occurs while scanning the second page and then only if a user operates
either the fax or copy function for more than 9,999 times.  It is not
known from where the alternate addressee is derived."
  );
  # http://www.xerox.com/downloads/usa/en/c/CERT_Xerox_Security_XRX05_002.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16527bbc");
  script_set_attribute(attribute:"solution", value:"Contact the Xerox Welcome Center and request software version 1.02.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/16");

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
  ess = get_kb_item_or_exit("www/xerox_workcentre/ess");

  # Test model number and software version against those in Xerox's
  # Security Bulletin XRX 05-002.
  if (
    model =~ "M24" &&
    (
      # nb: since the bulletin only talks of the version number
      #     but doesn't specify which, we'll check both.
      ver_inrange(ver:ess, low:"0", high:"1.01") ||
      ver_inrange(ver:ssw, low:"0", high:"1.01")
    )
  )
  security_note(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
