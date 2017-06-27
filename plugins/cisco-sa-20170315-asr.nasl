#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99266);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/12 14:42:16 $");

  script_cve_id("CVE-2017-3819");
  script_bugtraq_id(96913);
  script_osvdb_id(153840);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva65853");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170315-asr");
  script_xref(name:"IAVA", value:"2017-A-0091");

  script_name(english:"Cisco ASR StarOS SSH Login Parameter Handling Privilege Escalation (cisco-sa-20170315-asr)");
  script_summary(english:"Checks the StarOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco ASR device is affected by a privilege escalation
vulnerability in StarOS in the Secure Shell (SSH) subsystem due to
improper validation of parameters passed during SSH or SFTP login. An
authenticated, remote attacker can exploit this, by sending specially
crafted input during the SSH or SFTP login, to gain root privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170315-asr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?908587cb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva65853");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCva65853.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:staros");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr_5000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr_5500");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr_5700");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:asr_5000_series_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:asr_5500_series_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:asr_5700_series_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

# only affects ASR 5000/5500/5700 series systems
if (model !~ "^5[057]\d{2}$")
  audit(AUDIT_DEVICE_NOT_VULN, 'The ASR ' + model);

# Normalize train characters
version= toupper(version);

# For newer versions, We may be able to get the build number during detection
build = get_kb_item("Host/Cisco/StarOS/Build");
if (!empty_or_null(build))
  version += "." + build;

# defensive check for the pregmatches below
if (version !~ "^[\d\.]+\([\d\.]+" &&
    version !~ "^[\d\.]+([A-Z]{1,2}\d+)?\.\d+$")
  audit(AUDIT_DEVICE_NOT_VULN, "ASR " + model, version);

# old style of versioning 15.0(5439), style change mid 16.1, making
# all of the old style versions fall into the vulnerable range.
if ("(" >< version)
{
  major = pregmatch(pattern:"^([\d\.]+)\(", string:version);

  if(!isnull(major))
  {
    major = major[1];

    if (isnull(build))
    {
      build = pregmatch(pattern:"^[\d\.]+\(([\d\.]+)", string:version);
      if(!isnull(build))
      {
        build = build[1];

        # Set the train to an empty string, or it causes issues when
        # seeing if a patched version exists using NULL as the value
        train = '';
      }
      else
        exit(1, "Unable to extract build number.");
    }
  }
  else
    exit(1, "Unable to extract version number.");
}
else
{
  # extract major, train, and build for new style
  extract = pregmatch(pattern:"^([\d\.]+)\.([A-Z]{1,2}\d+)?\.?(\d+)?", string:version);
  if (!isnull(extract))
  {
    major = extract[1];
    train = extract[2];
    if (isnull(build))
      build = extract[3];
  }
}

# Defensive checking for versions that we haven't yet seen
if(empty_or_null(major) || empty_or_null(build))
  exit(1, "An error occurred during version extraction.");

fix_array = make_array(
  "18.8", make_array( "M0", 65044 ),
  "19.3", make_array( "V7", 66412 ),
  "19.5", make_array( "M0", 65050 ),
  "20.2", make_array( "A4", 65307, "B0", 66290, "V0", 64855 )
);

# Versions after 17.7.0 and prior to 18.7.4 are vulnerable
if (ver_compare(ver:major, minver:"17.7.1", fix:"18.7.4", strict:FALSE) < 0)
  fix = "18.7.4.65019";
else if (ver_compare(ver:major, minver:"19.0", fix:"19.5", strict:FALSE) < 0)
  fix = "19.5.0.65092";
else if (ver_compare(ver:major, minver:"20.0", fix:"20.2", strict:FALSE) < 0)
  fix = "20.2.1.64798";

if (major == "18.7.4" && int(build) < 65019)
  fix = "18.7.4.65019";
else if (major == "19.5.0" && int(build) < 65092)
  fix = "19.5.0.65092";
else if (major == "20.2.1" && int(build) < 64798)
  fix = "20.2.1.64798";

else if ( 
          !empty_or_null(fix_array[major]) && 
          !empty_or_null(train) && 
          int(build) < fix_array[major][train]
        )
  fix = major + "." + train + "." + string(fix_array[major][train]);

if (!isnull(fix))
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
