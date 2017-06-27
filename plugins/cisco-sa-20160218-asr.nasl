#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89051);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/05 16:04:16 $");

  script_cve_id("CVE-2016-1335");
  script_bugtraq_id(83304);
  script_osvdb_id(134724);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux22492");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160218-asr");

  script_name(english:"Cisco ASR 5000 Series StarOS SSH Subsystem Privilege Escalation (CSCux22492)");
  script_summary(english:"Checks the StarOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco ASR 5000 Series device is affected by a privilege
escalation vulnerability in the SSH subsystem due to improper handling
of multi-user public-key authentication. An authenticated, remote
attacker can exploit this, by establishing a connection from an
endpoint that was previously used for an administrator's connection,
to gain elevated privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160218-asr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0aab2ac");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCux22492");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCux22492.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:staros");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr_5000");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASR/Model", "Host/Cisco/StarOS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("Host/Cisco/StarOS");

version  = get_kb_item_or_exit("Host/Cisco/StarOS/Version");
model   = get_kb_item_or_exit("Host/Cisco/ASR/Model");

major = NULL;
build = NULL;
fix = NULL;
train = NULL;
new_ver_style = TRUE;

# only affects ASR 5000 series systems
if (model !~ "^5\d{3}$")
  audit(AUDIT_DEVICE_NOT_VULN, 'The ASR ' + model);

# Normalize train characters
version= toupper(version);

# defensive check for the eregmatches below
if (version !~ "^[\d\.]+\([\d\.]+" &&
    version !~ "^[\d\.]+[A-Z]{1,2}\d+\.\d+$")
  audit(AUDIT_DEVICE_NOT_VULN, "ASR " + model, version);

# old style of versioning 15.0(5439), style change mid 16.1, making
# all of the old style versions fall into the vulnerable range.
if ("(" >< version)
{
  major = eregmatch(pattern:"^([\d\.]+)\(", string:version);

  if(!isnull(major))
  {
    major = major[1];

    build = eregmatch(pattern:"^[\d\.]+\(([\d\.]+)", string:version);
      if(!isnull(build))
      {
        build = build[1];
        new_ver_style = FALSE;

        # Set the train to an empty string, or it causes issues when
        # seeing if a patched version exists using NULL as the value
        train = '';
      }
      else
        exit(1, "Unable to extract build number.");
  }
  else
    exit(1, "Unable to extract version number.");
}
else
{
  # extract major, train, and build for new style
  extract = eregmatch(pattern:"^([\d\.]+)\.([A-Z]{1,2}\d+)\.(\d+)", string:version);
  if (!isnull(extract))
  {
    major = extract[1];
    train = extract[2];
    build = extract[3];
  }
}

# Defensive checking for versions that we haven't yet seen
if (new_ver_style &&
   (empty_or_null(major) || empty_or_null(train) || empty_or_null(build)))
  exit(1, "An error occurred during version extraction.");
else if (!new_ver_style &&
   (empty_or_null(major) || empty_or_null(build)))
  exit(1, "An error occurred during version extraction.");

# For old and new styles- all < 19.3 are vuln
if (ver_compare(ver:major, fix:"19.3", strict:FALSE) < 0 )
  fix = "19.3.M0.62771";

# Per the advisory
else if (major == "19.3" && train == "M0" && int(build) < 62771 )
  fix = "19.3.M0.62771";

# For trains that are not in the M0 series, all vuln, with exceptions
else if (major == "19.3" && train != "M0")
  fix = "19.3.M0.62771";

# Per the advisory
else if (major == "20.0" && train == "M0" && int(build) < 62768)
  fix = "20.0.M0.62768";

# For trains that are not in the M0 series, all vuln, with exceptions
else if (major == "20.0" && train != "M0")
  fix = "20.0.M0.62768";

# These are all of the explicitly mentioned fixes, which are the exceptions
# in the trains that are not the M0 series.
known_fixes = make_array(
    "19.3", make_array( "A0", make_list("62430", "62460"),
                        "M0", make_list("62410", "62456", "62726", "62771"),
                        "T0", make_list("62421", "62463", "62725")
                      ),
    "20.0", make_array( "M0",  make_list("62373", "62453", "62480", "62490",
                                         "62492", "62724", "62748", "62792"),
                        "R0",  make_list("62757", "62808"),
                        "V0",  make_list("62729", "62707"),
                        "VC0", make_list("62385", "62464", "62510")
                      )
    );

# Check to see if there is a list if fixed builds for the major version and
# associated train.
if (fix && !is_list(known_fixes[major][train]))
{
  # Iterate through all of the fixed builds for each train, if one is found
  # then we are not vulnerable and we want to audit out.
  foreach fix_build (known_fixes[major][train])
    if (fix_build == build)
      fix = FALSE;
}

if (fix)
{
    report =
      '\n  Model             : ASR ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_DEVICE_NOT_VULN, "ASR " + model, version);
