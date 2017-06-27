#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70369);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/19 01:11:53 $");

  script_bugtraq_id(60844);
  script_osvdb_id(94662);

  script_name(english:"Xerox WorkCentre Multiple Unspecified Vulnerabilities (XRX13-006)");
  script_summary(english:"Checks system software version of Xerox WorkCentre devices");

  script_set_attribute(attribute:"synopsis",
    value:
"The remote multi-function device is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host
is a Xerox WorkCentre device that is affected by multiple, unspecified
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
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:workcentre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("xerox_workcentre_detect.nasl");
  script_require_keys("www/xerox_workcentre", "www/xerox_workcentre/model", "www/xerox_workcentre/ssw");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Get model and system software version
model = get_kb_item_or_exit("www/xerox_workcentre/model");
ssw_version = get_kb_item_or_exit("www/xerox_workcentre/ssw");

ssw = split(ssw_version, sep:".", keep:FALSE);

# Store version as a string with preceding 0's.
# ie: 071.030.100.06400
ssw_str = ssw;

# Store version as an integer without preceding 0's
# ie: 71.30.100.6400
for (i=0; i<max_index(ssw); i++)
   ssw[i] = int(ssw[i]);

# Variables
fix = NULL;
patch_ver = '';
patch = '';
not_affected = FALSE;
patched = FALSE;


# WorkCentre 5845/5855/5865/5875/5890
# SSW Versions < 071.190.103.15600  are affected
if (model =~ "^58([4567]5|90)")
{
  patch_ver = "071.190.103.15600";

  if (
    (ssw_str[0] =~ "^0" && ssw[0] < 71) ||
    (ssw_str[0] == '071' && ssw[1] < 190) ||
    (ssw_str[0] == '071' && ssw_str[1] == '190' && ssw[2] < 103) ||
    (ssw_str[0] == '071' && ssw_str[1] == '190' && ssw_str[2] == '103' && ssw_str[3] < 15600)
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

# WorkCentre 7220/7225
# SSW Versions < 071.030.103.15600  are affected
if (model =~ "^722[05]")
{
  patch_ver = "071.030.103.15600 ";

  if (
    (ssw_str[0] =~ "^0" && ssw[0] < 71) ||
    (ssw_str[0] == '071' && (ssw_str[1] =~ "^0" && ssw[1] < 30)) ||
    (ssw_str[0] == '071' && ssw_str[1] == '030' && ssw[2] < 103) ||
    (ssw_str[0] == '071' && ssw_str[1] == '030' && ssw_str[2] == '103' && ssw_str[3] < 15600)
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

# WorkCentre 7830/7835
# SSW Versions less than 071.010.103.15600 are affected
if (model =~ "^783[05]")
{
  patch_ver = "071.010.103.15600";

  if (
    (ssw_str[0] =~ "^0" && ssw[0] < 71) ||
    (ssw_str[0] == '071' && (ssw_str[1] =~ "^0" && ssw[1] < 10)) ||
    (ssw_str[0] == '071' && ssw_str[1] == '010' && ssw[2] < 103) ||
    (ssw_str[0] == '071' && ssw_str[1] == '010' && ssw_str[2] == '103' && ssw_str[3] < 15600)
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

# WorkCentre 7845/7855
# SSW Versions less than 071.040.103.15600 are affected
if (model =~ "^78[45]5")
{
  patch_ver = "071.040.103.15600";

  if (
    (ssw_str[0] =~ "^0" && ssw[0] < 71) ||
    (ssw_str[0] == '071' && (ssw_str[1] =~ "^0" && ssw[1] < 40)) ||
    (ssw_str[0] == '071' && ssw_str[1] == '040' && ssw[2] < 103) ||
    (ssw_str[0] == '071' && ssw_str[1] == '040' && ssw_str[2] == '103' && ssw_str[3] < 15600)
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
  audit(AUDIT_PATCH_INSTALLED, "System SW Version " + patch + " for Xerox WorkCentre " + model);

if (not_affected)
  audit(AUDIT_INST_VER_NOT_VULN, "Xerox WorkCentre "+model +" System SW", ssw_version);

if (!isnull(fix))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model                             : Xerox WorkCentre ' + model +
      '\n  Installed System Software version : ' + ssw_version +
      '\n  Fixed System Software version     : ' + fix + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_HOST_NOT, "an affected Xerox WorkCentre model");
