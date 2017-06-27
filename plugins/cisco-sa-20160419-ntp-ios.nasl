#TRUSTED 54184cf3960834c66fbb54b8a740e1ce945e3106ad151dd9ef4f5b08cf496e62b75e948410789d0364ba88102896f659db664919b081674ea081c5384b54cf204fc582b7a03ed063364ef2a7597b8cabb5e1c55a22e288a4a3433ca05857832de5b9d7000991a7b2aed8ff083a2f5de1edad39dc414801ed40ebb7087825ed2c95a6e73af8368a8cb73e717d420e52c2313a22ce9890932b5abefe6a8725bb638c581f7a9f61eb0464eacc7b2983d91518519b930995768cc84fd1df34f0a208ae7496cfa52eff9fd93ac727933f35e1fe8817d98027ce842c7e2f88be94e2b36070f119ea897eb58bfe73b5ac13fe091a291d36bce2101b6b88639fe30180dfdfa7f256d98a34e3e8bc8c4802e223901e0671886db2edc026912297ca9fc02ce5c24e76ddb2b9a5ef9bd2db711b078837d142c8bb5c98a0fb5ecef0f50913a51387535f12f93e84a37f387aff4709cc4aa6895cc6e513c8542a8e65ae906a8a4a6764f831e251d57881305ebd3df5ff6f57c5c85169b11557a91d0fc3167b58a8887ad362ccb87e55057379dcc456dfe9c16cd1dfac0ea216a941d4ba0b0efd6a16a015dca2ee86cdcb201af8253823ea34c43d88e3b97df7ef26bcbaa2f3d54692e3259db83b9384d133668751629521f0fd9b49323a22c111e9970358f75515d51f9d55b1d0e1349e6f15b6b9954d32e48b1454e87355b5480a60216e9cd2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90861);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/05/03");

  script_cve_id("CVE-2016-1384");
  script_osvdb_id(137351);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux46898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160419-ios");

  script_name(english:"Cisco IOS NTP Subsystem Unauthorized Access (cisco-sa-20160419-ios)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by an unauthorized access
vulnerability in the NTP subsystem due to a failure to check the
authorization of certain NTP packets. An unauthenticated, remote
attacker can exploit this issue, via specially crafted NTP packets, to
control the time of the remote device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160419-ios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8965288b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCux46898.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
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

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln version
# Below are from CVRF
if ( ver == '15.1(1)S' ) flag++;
if ( ver == '15.1(1)S1' ) flag++;
if ( ver == '15.1(1)S2' ) flag++;
if ( ver == '15.1(2)S' ) flag++;
if ( ver == '15.1(2)S1' ) flag++;
if ( ver == '15.1(2)S2' ) flag++;
if ( ver == '15.1(3)S' ) flag++;
if ( ver == '15.1(3)S0a' ) flag++;
if ( ver == '15.1(3)S1' ) flag++;
if ( ver == '15.1(3)S2' ) flag++;
if ( ver == '15.1(3)S3' ) flag++;
if ( ver == '15.1(3)S4' ) flag++;
if ( ver == '15.1(3)S5' ) flag++;
if ( ver == '15.1(3)S5a' ) flag++;
if ( ver == '15.1(3)S6' ) flag++;
if ( ver == '15.5(3)M' ) flag++;
if ( ver == '15.5(3)M0a' ) flag++;
if ( ver == '15.5(3)M1' ) flag++;
if ( ver == '15.5(1)S' ) flag++;
if ( ver == '15.5(1)S1' ) flag++;
if ( ver == '15.5(1)S2' ) flag++;
if ( ver == '15.5(1)S3' ) flag++;
if ( ver == '15.5(1)S4' ) flag++;
if ( ver == '15.5(2)S' ) flag++;
if ( ver == '15.5(2)S1' ) flag++;
if ( ver == '15.5(2)S2' ) flag++;
if ( ver == '15.5(2)S3' ) flag++;
if ( ver == '15.5(3)S' ) flag++;
if ( ver == '15.5(3)S0a' ) flag++;
if ( ver == '15.5(3)S1' ) flag++;
if ( ver == '15.5(3)S1a' ) flag++;
if ( ver == '15.5(3)SN' ) flag++;
if ( ver == '15.5(2)T' ) flag++;

# NTP check
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ntp_status", "show ntp status");
  # Check for traces of ntp
  if (check_cisco_result(buf))
  {
    if (
      "%NTP is not enabled." >< buf &&
      "system poll" >!< buf &&
      "Clock is" >!< buf
    ) audit(AUDIT_HOST_NOT, "affected because NTP is not enabled");
  }
  else if (cisco_needs_enable(buf)) override = 1;
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCux46898' +
      '\n  Installed release : ' + ver +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
