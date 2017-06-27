#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18268);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/11/05 20:35:00 $");

  script_bugtraq_id(12782);
  script_osvdb_id(14658);

  script_name(english:"Xerox Document Centre MicroServer Web Server Directory Navigation Crafted URL DoS (XRX05-004)");
  script_summary(english:"Checks the version of Xerox device");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to a denial of service attack.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host
is a Xerox Document Centre or WorkCentre device with an embedded web
server that is prone to remote denial of service attacks.
Specifically, memory on the affected device can become corrupted,
triggering a crash and restart, when the web server processes a
malicious URI designed to navigate through various unspecified
directories."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/cert_XRX05_004.pdf" );
  script_set_attribute(attribute:"see_also", value:"http://www.xerox.com/downloads/usa/en/c/CERT_Xerox_Security_XRX04-07.pdf" );
  script_set_attribute(attribute:"solution", value:"Apply the P10 or P11 patches as described in the Xerox bulletins.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:workcentre");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:document_centre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");

  script_dependencies("xerox_document_centre_detect.nasl", "xerox_workcentre_detect.nasl");
  script_require_ports("www/xerox_document_centre", "www/xerox_workcentre");

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
#
# - Document Centre devices.
if (get_kb_item("www/xerox_document_centre"))
{
  model = get_kb_item_or_exit("www/xerox_document_centre/model");
  ess = get_kb_item_or_exit("www/xerox_document_centre/ess");

  # No need to check further if ESS ends with ".P11" since that
  # indicates the patch has already been applied.
  if (ess && ess =~ "\.P11") audit(AUDIT_HOST_NOT, "affected");

  # Test model number and ESS level against those in Xerox's
  # Security Bulletin XRX05-004.
  if (
    # nb: models 535/545/555 with ESS <= 27.18.017
    (model =~ "5[345]5" && ver_inrange(ver:ess, low:"0", high:"27.18.017")) ||

    # nb: models 460/470/480/490 with ESS 19.01.037 - 19.05.521 or 19.5.902 - 19.5.912.
    (
      model =~ "4[6-9]0" &&
      (
        ver_inrange(ver:ess, low:"19.01.037", high:"19.05.521") ||
        ver_inrange(ver:ess, low:"19.5.902", high:"19.5.912")
      )
    ) ||

    # nb: models 420/426/432/440 with ESS 2.1.2 - 2.3.21
    (model =~ "4(2[06]|32|40)" && ver_inrange(ver:ess, low:"2.1.2", high:"2.3.21")) ||

    # nb: models 425/432/440 with ESS 3.0.5.4 - 3.2.30
    (model =~ "4(25|32|40)" && ver_inrange(ver:ess, low:"3.0.5.4", high:"3.2.30")) ||

    # nb: model 430 with ESS 3.3.24 - 3.3.30
    (model =~ "430" && ver_inrange(ver:ess, low:"3.3.24", high:"3.3.30"))
  )
  security_hole(0);
  exit(0);
}

# - WorkCentre devices.
if (get_kb_item("www/xerox_workcentre"))
{
  model = get_kb_item_or_exit("www/xerox_workcentre/model");
  ess = get_kb_item_or_exit("www/xerox_workcentre/ess");

  # No need to check further if ESS ends with ".P10" since that
  # indicates the patch has already been applied.
  if (ess && ess =~ "\.P10") audit(AUDIT_HOST_NOT, "affected");

  # Test model number and software version against those in Xerox's
  # Security Bulletin XRX04-007.
  if (
    # nb: models M35/M45/M55 or Pro 35/45/55 with ESS 1.01.108.1 - 1.02.372.1
    (model =~ "(M|Pro )[345]5" && ver_inrange(ver:ess, low:"1.01.108.1", high:"1.02.372.1")) ||

    # nb: models 32/40 Color with ESS 01.00.060 - 01.02.072.1
    (model =~ "(32|40)C" && ver_inrange(ver:ess, low:"01.00.060", high:"01.02.072.1"))
  )
  security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
