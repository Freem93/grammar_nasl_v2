#TRUSTED 0e70df3a4c344ea9e4aec9d2274d80cd0273814ec243b83648dd0595aff56ea3a818183fa724914322768d707b4561a091d7cf7527e4f291647396bb9f17bc3caf7565521f0840ebddae8e4bc1ecef177a8b161628e52d9400b8f7500863af7f03e44cd4535152ef8c61b7f6bcb2b8904ce8184cb19d34e6dc656b3be6c2b052a1a80e1d5b68967f27684e574efb7d74b7bdc5de05e459033940ef2d73f1e9ba3b318ba14613a7bceefe5213d3518a1497c278adc372eed37b2d57f8225b800ef2ef419d9fe9bfbdc8fb52a75dc166701b2c676c80480a6ade0baf840c02b3a7f52aed97527c43f9c1430c6ad0d537b32b434e606cdd5fa33ec4f06f067945db2df99395842de486a5264e7478a590237fd1480b3e9179f0d4a77743d51d4aa771d2b7072c5288200fccb92baae872db0aa52d6a4a15fabda61833ba757b6e33c0f9014473357965c7905f2cddfbefdfb1674eb08f674910ac51767dac105968dcfb5494cfefdd11f01faea9b7fc052fef1cb08ad714197e13af7c826cda2b00b0a662551a3295e9cc4a9b192b886db6aa56b9a47d58c49d6441a583b3321f23af4170bb80d98af4c13f1d416f4d220545a039e5a299be5a11d131574259bd54fc6a65f2b03f7ecccb2cea1a450fcebd2165fb077ff07d373b19e550ada7f9e995f8f91fede2001cf7e703b02bbc758df78348b9b4b97158bc8f73864354a0f8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93122);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/08/26");

  script_cve_id("CVE-2016-1459");
  script_bugtraq_id(91800);
  script_osvdb_id(141562);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz21061");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160715-bgp");

  script_name(english:"Cisco IOS Software Border Gateway Protocol Message Processing DoS (cisco-sa-20160715-bgp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS Software running on the remote device is missing a
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

app_name = "Cisco IOS";
version  = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (
  version != "Cisco IOS 12.4(19a)" &&
  version != "Cisco IOS 12.4(24)GC4" &&
  version != "Cisco IOS 12.4(24)GC5" &&
  version != "Cisco IOS 12.4(15)T17" &&
  version != "Cisco IOS 12.4(4)XC7" &&
  version != "Cisco IOS 12.4(22)YB2" &&
  version != "Cisco IOS 15.0(1)EX" &&
  version != "Cisco IOS 15.0(1)M" &&
  version != "Cisco IOS 15.0(1)M10" &&
  version != "Cisco IOS 15.0(1)M9" &&
  version != "Cisco IOS 15.0(1)S" &&
  version != "Cisco IOS 15.0(2)SG" &&
  version != "Cisco IOS 15.0(1)SY" &&
  version != "Cisco IOS 15.1(4)GC2" &&
  version != "Cisco IOS 15.1(4)M10" &&
  version != "Cisco IOS 15.1(3)T4" &&
  version != "Cisco IOS 15.2(4)GC3" &&
  version != "Cisco IOS 15.2(4)M10" &&
  version != "Cisco IOS 15.2(3)T4" &&
  version != "Cisco IOS 15.3(3)M" &&
  version != "Cisco IOS 15.3(3)M7" &&
  version != "Cisco IOS 15.3(2)T4" &&
  version != "Cisco IOS 15.4(3)M5" &&
  version != "Cisco IOS 15.4(2)T4" &&
  version != "Cisco IOS 15.5(3)M3" &&
  version != "Cisco IOS 15.5(2)T3"
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
