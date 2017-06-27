#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95538);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/07 20:46:53 $");

  script_cve_id("CVE-2016-6466");
  script_bugtraq_id(94361);
  script_osvdb_id(147431);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva13631");
  script_xref(name:"IAVB", value:"2016-B-0168");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161116-asr");

  script_name(english:"Cisco ASR 5000 Series ipsecmgr Service DoS (cisco-sa-20161116-asr)");
  script_summary(english:"Checks the StarOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco ASR 5000 Series device is affected by a denial of
service vulnerability in the ipsecmgr service of StarOS due to
improper processing of Internet Key Exchange (IKE) messages. An
unauthenticated, remote attacker can exploit this vulnerability, via
specially crafted IKE messages, to cause a reload of the ipsecmgr
service, resulting in all active IPSEC tunnels being terminated and
preventing new tunnels from establishing until the service has
restarted.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161116-asr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd9e6b40");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva13631");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCva13631.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:staros");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr_5000");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

# only affects ASR 5000/5500 series systems
if (model !~ "^5[05]\d{2}$")
  audit(AUDIT_DEVICE_NOT_VULN, 'The ASR ' + model);

# Normalize train characters
version= toupper(version);

# defensive check for the eregmatches below
if (version !~ "^[\d\.]+\([\d\.]+" &&
    version !~ "^[\d\.]+([A-Z]{1,2}\d+)?\.\d+$")
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
  extract = eregmatch(pattern:"^([\d\.]+)\.([A-Z]{1,2}\d+)?\.?(\d+)", string:version);
  if (!isnull(extract))
  {
    major = extract[1];
    train = extract[2];
    build = extract[3];
  }
}

fix_array = make_array(
  "20.2", make_array( "A4", 65307, "V1", 65353 ),
  "20.3", make_array( "M0", 65037, "T0", 65043 ),
  "21.0", make_array( "M0", 64595, "V0", 65052, "VC0", 64639 ),
  "21.1", make_array( "A0", 64861, "PP0", 65270, "R0", 65130, "VC0", 64898 ),
  "21.2", make_array( "A0", 65147 )
  );

# Defensive checking for versions that we haven't yet seen
if(empty_or_null(major) || empty_or_null(build))
  exit(1, "An error occurred during version extraction.");

# No fixes prior to 20.2.3/20.2.a4
if (ver_compare(ver:major, fix:"20.2", strict:FALSE) < 0 )
  fix = "20.2.3.65026";

else if (major == "20.2.3" && int(build) < 65026)
  fix = "20.2.3.65026";

else if (major == "21.0.0" && empty_or_null(train) && int(build) < 65256)
  fix = "21.0.0.65256";

else if ( 
          !empty_or_null(fix_array[major]) && 
          !empty_or_null(train) && 
          int(build) < fix_array[major][train]
        )
  fix = major + "." + train + "." + string(fix_array[major][train]);


if (fix)
{
    report =
      '\n  Model             : ASR ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else
  audit(AUDIT_DEVICE_NOT_VULN, "ASR " + model, version);
