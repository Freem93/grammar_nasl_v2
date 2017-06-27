#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70370);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/11/02 21:39:30 $");

  script_bugtraq_id(60844);
  script_osvdb_id(94662);

  script_name(english:"Xerox ColorQube Multiple Unspecified Vulnerabilities (XRX13-006)");
  script_summary(english:"Checks system software version of Xerox ColorQube devices");

  script_set_attribute(attribute:"synopsis",
    value:
"The remote multi-function device is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host
is a Xerox ColorQube device that is affected by multiple, unspecified
vulnerabilities."
  );
  # http://www.xerox.com/download/security/security-bulletin/19539-4ea9c6a30de43/cert_XRX13-006_v1.3.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14b5e14c");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the appropriate cumulative update as described in the Xerox
security bulletin in the referenced URL."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:colorqube");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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
patch_ver = "071.180.203.15600";
patch = '';
not_affected = FALSE;
patched = FALSE;

# ColorQube 9301/9302/9303
# Versions 061.180.101.04101 to 061.180.223.11601 need to perform a special
# upgrade process as outlined in the Xerox security bulletin
if (model =~ "^930[123]")
{
  if(
    (ssw_version =~ "061\.180\.101\." && (ssw_str[3] =~ "^0" && ssw[3] >= 4101)) ||
    (ssw_version =~ "061\.180\.101\." && ssw_str[3] >= 1) ||
    (ssw_version =~ "061\.180\.(10[2-9]|1[1-9][0-9]|2[0-1][0-9]|22[0-2])") ||
    (ssw_version =~ "061\.180\.223\." && ssw[3] <= 11601)
  )
  {
    fix = "Refer to the referenced URL for upgrade instructions.";
  }
  # Versions 071.180.203.05402 to 071.180.203.06400 need to upgrade
  else if (
    (ssw_version =~ "071\.180\.203\." &&
    (ssw_str[3] =~ "^0" && (ssw[3] >= 5402 && ssw[3] <= 6400)))
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

if (patched)
  audit(AUDIT_PATCH_INSTALLED, "System SW Version " + patch + " for Xerox ColorQube " + model);

if (not_affected)
  audit(AUDIT_INST_VER_NOT_VULN, "Xerox ColorQube "+model +" System SW", ssw_version);

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
