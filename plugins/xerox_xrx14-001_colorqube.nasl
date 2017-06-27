#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72581);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/11/02 21:39:30 $");

  script_bugtraq_id(65468);
  script_osvdb_id(103046);

  script_name(english:"Xerox ColorQube ConnectKey Controller Multiple Unspecified Vulnerabilities (XRX14-001)");
  script_summary(english:"Checks system software version of Xerox ColorQube devices");

  script_set_attribute(attribute:"synopsis",
    value:
"The remote multi-function device is affected by multiple, unspecified
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host is
a Xerox ColorQube device with a ConnectKey Controller and it is affected
by multiple, unspecified vulnerabilities."
  );
  # http://www.xerox.com/download/security/security-bulletin/f89c-4f1d6f982b8a7/cert_XRX14-001_v1.0.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd44d737");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the appropriate cumulative update as described in the Xerox
security bulletin in the referenced URL."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:colorqube");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("xerox_colorqube_detect.nbin");
  script_require_keys("www/xerox_colorqube", "www/xerox_colorqube/model", "www/xerox_colorqube/ssw");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Get model and system software version
model = get_kb_item_or_exit("www/xerox_colorqube/model");
ssw_version = get_kb_item_or_exit("www/xerox_colorqube/ssw");

ssw = split(ssw_version, sep:".", keep:FALSE);

# Store version as a string with preceding 0's.
# ie: 061.180.101.04101
ssw_str = ssw;

# Store version as an integer without preceding 0's
# ie: 61.180.101.4101
for (i=0; i<max_index(ssw); i++)
   ssw[i] = int(ssw[i]);

# Variables
fix = NULL;
patch_ver = "071.161.203.15600";
patch = '';
not_affected = FALSE;
patched = FALSE;

# ColorQube 8700/8900
# Versions 071.160.101.35100 to 071.160.223.10700
if (model =~ "^8[79]00([^0-9]|$)")
{
  if (
    (ssw_version =~ "071\.160\.101\." && ssw[3] >= 35100) ||
    (ssw_version =~ "071\.160\." &&
      (ssw[2] > 101 && ssw[2] < 223) && ssw[3] >= 1) ||
    (ssw_version =~ "071\.160\.223\." && ssw[3] <= 10700)
  )
  {
    fix = "Refer to the referenced URL for upgrade instructions.";
  }
  # Versions 071.161.203.09300 to 071.161.203.15600 need to upgrade
  else if (
    ssw_version =~ "071\.161\.203\." &&
    (ssw[3] >= 9300 && ssw[3] < 15600)
  )
  {
    fix = patch_ver;
  }
  else if (ssw_version == patch_ver)
  {
    patched = TRUE;
    patch = patch_ver;
  }
  else
  {
    not_affected = TRUE;
  }
}

if (patched) audit(AUDIT_PATCH_INSTALLED, "System SW Version " + patch + " for Xerox ColorQube " + model);

if (not_affected) audit(AUDIT_INST_VER_NOT_VULN, "Xerox ColorQube "+model +" System SW", ssw_version);

if (!isnull(fix))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model                             : Xerox ColorQube ' + model +
      '\n  Installed System Software version : ' + ssw_version +
      '\n  Fixed System Software version     : ' + fix + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_HOST_NOT, "an affected Xerox ColorQube model");
