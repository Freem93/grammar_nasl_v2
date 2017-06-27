#TRUSTED 62371a8e26030bed4e388fc15e557159eba55fbf13883fc29dc1d399142977083cd6046ca07e6088b6b0e4838ea4716ad4cb3cb281e75f458e66581efe208493e51bfa154422f10215dcee57030633f5dec9bef0dcce7c9b758412b81d967d0d612c08046b1cbef9b31e25eaf1bee208c4c7a47ec3def6d728b954c4a2b44c576c2396e4c3e7fdaab5117fc8af8f2c40d192ad86d0f8dc974a6096cd82398c68998433cdd6e8097974ef516ad765ecf3a4a89e097743b81a1824757f23334c01ca05f7284a7ef55c1e50e9d5cb2539e134c2542fc27af4f167a830f03284bc946b30cca7fa2a9b6ed2724608da3f2a1f2ff6e24c47b191ac1b926cb11624b3ce6c03ad11b87d1a2de61e157d96ddb9c4f41b85ac9d6048b34df2db9f1d920854742c81d56bb2c0d4ca23e356ec7ed8e780151a431a238897254f9bf58beee29d338254db9658e438a61b984e217849aa459e02d712b72a1275beb2250f28c629a5cb31e9405c233395b66cdcc3e1b56afb60841b228efd84c9d46a35cdd8065bb3c37f05627d1d7671b725b2edf4d8636753b9cdaa82e723e8c56eea296dd51ca875e873e81ad6e47cd41153da28bf770c62c744fc7f638e2df40351c1c1574c8ff2c51751e31dde85c5198686a8d6d3bb156cb65848e41c5be088c36f1366f53b5bacb76dce28bde2c6b8aba743ef4e073e53864ba834735f84dafd41abdefc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93123);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/08/26");

  script_cve_id("CVE-2016-1459");
  script_bugtraq_id(91800);
  script_osvdb_id(141562);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz21061");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160715-bgp");

  script_name(english:"Cisco IOS XE Software Border Gateway Protocol Message Processing DoS (cisco-sa-20160715-bgp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE Software running on the remote device is missing a
security patch. It is, therefore, affected by a denial of service
vulnerability in the Border Gateway Protocol (BGP) message processing
functions due to improper processing of BGP attributes. An
authenticated, remote attacker can exploit this, via specially crafted
BGP messages under certain unspecified conditions, to cause the
affected device to reload.

Note that Nessus has not tested for the presence of the workarounds
referenced in the vendor advisory.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160715-bgp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94ed1c7e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20160715-bgp. Alternatively, set a 'maxpath-limit' value for
BGP MIBs or suppress the use of BGP MIBs.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

app_name = "Cisco IOS-XE";
version  = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

if (
  version != "Cisco IOS XE Software 3.13S 3.13.5S" &&
  version != "Cisco IOS XE Software 3.13S 3.13.2S" &&
  version != "Cisco IOS XE Software 3.13S 3.13.3S" &&
  version != "Cisco IOS XE Software 3.13S 3.13.4S" &&
  version != "Cisco IOS XE Software 3.14S 3.14.0S" &&
  version != "Cisco IOS XE Software 3.14S 3.14.1S" &&
  version != "Cisco IOS XE Software 3.14S 3.14.2S" &&
  version != "Cisco IOS XE Software 3.14S 3.14.3S" &&
  version != "Cisco IOS XE Software 3.14S 3.14.4S" &&
  version != "Cisco IOS XE Software 3.15S 3.15.1cS" &&
  version != "Cisco IOS XE Software 3.15S 3.15.3S" &&
  version != "Cisco IOS XE Software 3.15S 3.15.2S" &&
  version != "Cisco IOS XE Software 3.17S 3.17.0S" &&
  version != "Cisco IOS XE Software 3.17S 3.17.2S" &&
  version != "Cisco IOS XE Software 3.17S 3.17.1S" &&
  version != "Cisco IOS XE Software 3.16S 3.16.3S" &&
  version != "Cisco IOS XE Software 3.16S 3.16.0cS" &&
  version != "Cisco IOS XE Software 3.16S 3.16.1aS" &&
  version != "Cisco IOS XE Software 3.16S 3.16.2S"
)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

# We don't check for workarounds, so only flag if paranoid
if (report_paranoia < 2) audit(AUDIT_PARANOID);

## If the target does not have BGP active, exit

caveat = '';

# Since cisco_ios_version.nasl removes "Host/local_checks_enabled" when report_paranoia > 1,
# we will try to run the command without checking for local checks; a failure will return NULL
buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_bgp", "show ip bgp", 0);

# check_cisco_result() would cause false positives on devices that do not support BGP,
# so we are only looking for authorization-related error messages or NULL
if ( ("% This command is not authorized" >< buf) || ("ERROR: Command authorization failed" >< buf) || empty_or_null(buf) )
  caveat = cisco_caveat();
else if (!preg(pattern:"BGP table version", multiline:TRUE, string:buf))
  audit(AUDIT_HOST_NOT, "affected because BGP is not active");

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCuz21061' +
    '\n  Installed release : ' + version +
    '\n  Fixed release     : ' + report_fixed_version +
    '\n';

  security_warning(port:0, extra:report + caveat);
}
else security_warning(port:0, extra:caveat);
