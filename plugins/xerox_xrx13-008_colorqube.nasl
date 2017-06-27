#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70660);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/08/08 14:24:01 $");

  script_bugtraq_id(63270);
  script_osvdb_id(98840);

  script_name(english:"Xerox ColorQube Unspecified Remote Protocol Authorization Bypass (XRX13-008)");
  script_summary(english:"Checks system software version of Xerox ColorQube devices");

  script_set_attribute(attribute:"synopsis",
    value:
"The remote multi-function device is affected by an authorization bypass
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its model number and software version, the remote host is
a Xerox ColorQube device that is affected by an unspecified, remote
protocol authorization bypass vulnerability."
  );
  # http://www.xerox.com/download/security/security-bulletin/148ae-4e940cfff7450/cert_XRX13-008_v1.0.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26cab4e8");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the appropriate cumulative update as described in the Xerox
security bulletin in the referenced URL."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:colorqube");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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
not_affected = FALSE;
patched = FALSE;
fix = NULL;

# ColorQube 9201/9202/9203
# CBC versions - 060.050.xxx.xxx   SBC versions - 060.080.xxx.xxx
# http://download.support.xerox.com/pub/drivers/CQ9201_CQ9202_CQ9203/firmware/linux/fr_CA/ColorQube_92xx_Software_Identification.pdf
#
# CBC versions < 061.050.223.04800 are affected
# SBC versions < 061.080.223.05100 are affected

if (model =~ "^920[123]")
{
  if (ssw_str[0] =~ "^0" && ssw[0] < 61)
  {
    fix = "061.050.223.04800 (CBC) / 061.080.223.05100 (SBC)";
  }
  # CBC
  else if(
    (ssw_str[0] == "061" && ssw_str[1] =~ "^0" && ssw[1] <= 50)
  )
  {
    patch_ver = "061.050.223.04800";
    if (
      (ssw_str[0] == "061" && ssw_str[1] == "050" && ssw[2] < 223) ||
      (ssw_str[0] == "061" && ssw_str[1] == "050" && ssw_str[2] == "223" && ssw_str[3] =~ "^0" && ssw[3] < 4800)
    )
    {
      fix = patch_ver;
    }
    else if (ssw_version == patch_ver)
    {
      patched = TRUE;
      patch = patch_ver;
    }
    else not_affected = TRUE;
  }
  # SBC
  else if (ssw_str[0] == "061" && ssw_str[1] == "080")
  {
    patch_ver = "061.080.223.05100";
    if (
      (ssw_str[0] == "061" && ssw_str[1] == "080" && ssw[2] < 223) ||
      (ssw_str[0] == "061" && ssw_str[1] == "080" && ssw_str[2] == "223" && ssw_str[3] =~ "^0" && ssw[3] < 5100)
    )
    {
      fix = patch_ver;
    }
    else if (ssw_version == patch_ver)
    {
      patched = TRUE;
      patch = patch_ver;
    }
    else not_affected = TRUE;
  }
  else not_affected = TRUE;
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
