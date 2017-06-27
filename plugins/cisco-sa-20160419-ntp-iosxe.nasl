#TRUSTED 0093b1ca28457a5ba161f1260d7d61fc4d67c4d9b8d55c776c40655978ad84e96423e3f69c89a252e9a649e50e5af679f64cbaa6a92f96a695d332fde834b2e53fdf65cf34cffbfebff957d5dd56decb4d32b6900ef115535efa6c48cae59b54dfdb1d351a275ca8a89dee0bc913308758ea941d8cf892180588750f8699c931bb733de38c65d477104121cfd5a76bc2e64f6b60c0183894707245bfd519c7dc788cd2bfbb6d2dd9efcbce87bf39bba3a5d997079b5ab852e0941e9236a104a8d95b43ea73d81144f8506ac94a188a1df8ac4da607044bfc3696f03b8d16d04d0797a1c050c9699e57adb9f957c979e3a8b1dcdfe81a3d94421aecb60a94b438553dfb49f35ddb5c4a46e9bc12f714547e5c20bcd84b6c3f961ff1e35cc64c37812bafae303325c6adf00208a4296961d18499abc854d1435f382ed568b2328e0f58445fb969369da43a9c9b38fa268e6978ccd06df5d5e043f4f7d142f4674141a2a2cf4e53dde46841b5272554df85908ec364fefa388d03ba04cf3508e3c6e8de14b4a6270a90a2c0fc2fd903a7c7c2dcc7bcba9e7fdfc0edf8dc03d315345dd987c56d67996b49ecdcb9701a4e39324b1164b420d57f6a33de8c2d85af441fa92918514ff956e5aea5992adb54749ef1ffb305c533158c1c3964c32eca935ed6d931db82e25ae44bf4756ae8adea396f2631de807b1cfe6597b4f43d3b0c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90862);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/08/19");

  script_cve_id("CVE-2016-1384");
  script_osvdb_id(137351);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux46898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160419-ios");

  script_name(english:"Cisco IOS XE NTP Subsystem Unauthorized Access (cisco-sa-20160419-ios)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by an unauthorized access
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
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

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

# Check for vuln version
if ( ver == '3.2.0JA' ) flag++;
if ( ver == '3.8.0E' ) flag++;
if ( ver == '3.8.1E' ) flag++;
if ( ver == '3.8.0EX' ) flag++;
if ( ver == '3.2.0S' ) flag++;
if ( ver == '3.2.1S' ) flag++;
if ( ver == '3.2.2S' ) flag++;
if ( ver == '3.2.3S' ) flag++;
if ( ver == '3.2.0SE' ) flag++;
if ( ver == '3.2.1SE' ) flag++;
if ( ver == '3.2.2SE' ) flag++;
if ( ver == '3.2.3SE' ) flag++;
if ( ver == '3.2.0SG' ) flag++;
if ( ver == '3.2.1SG' ) flag++;
if ( ver == '3.2.2SG' ) flag++;
if ( ver == '3.2.3SG' ) flag++;
if ( ver == '3.2.4SG' ) flag++;
if ( ver == '3.2.5SG' ) flag++;
if ( ver == '3.2.6SG' ) flag++;
if ( ver == '3.2.7SG' ) flag++;
if ( ver == '3.2.8SG' ) flag++;
if ( ver == '3.2.9SG' ) flag++;
if ( ver == '3.2.10SG' ) flag++;
if ( ver == '3.2.0XO' ) flag++;
if ( ver == '3.2.1XO' ) flag++;
if ( ver == '3.3.0S' ) flag++;
if ( ver == '3.3.1S' ) flag++;
if ( ver == '3.3.2S' ) flag++;
if ( ver == '3.3.0SE' ) flag++;
if ( ver == '3.3.1SE' ) flag++;
if ( ver == '3.3.2SE' ) flag++;
if ( ver == '3.3.3SE' ) flag++;
if ( ver == '3.3.4SE' ) flag++;
if ( ver == '3.3.5SE' ) flag++;
if ( ver == '3.3.0SG' ) flag++;
if ( ver == '3.3.1SG' ) flag++;
if ( ver == '3.3.2SG' ) flag++;
if ( ver == '3.3.0SQ' ) flag++;
if ( ver == '3.3.1SQ' ) flag++;
if ( ver == '3.3.0XO' ) flag++;
if ( ver == '3.3.1XO' ) flag++;
if ( ver == '3.3.2XO' ) flag++;
if ( ver == '3.4.0S' ) flag++;
if ( ver == '3.4.0aS' ) flag++;
if ( ver == '3.4.1S' ) flag++;
if ( ver == '3.4.2S' ) flag++;
if ( ver == '3.4.3S' ) flag++;
if ( ver == '3.4.4S' ) flag++;
if ( ver == '3.4.5S' ) flag++;
if ( ver == '3.4.6S' ) flag++;
if ( ver == '3.4.0SG' ) flag++;
if ( ver == '3.4.1SG' ) flag++;
if ( ver == '3.4.2SG' ) flag++;
if ( ver == '3.4.3SG' ) flag++;
if ( ver == '3.4.4SG' ) flag++;
if ( ver == '3.4.5SG' ) flag++;
if ( ver == '3.4.6SG' ) flag++;
if ( ver == '3.4.7SG' ) flag++;
if ( ver == '3.4.0SQ' ) flag++;
if ( ver == '3.4.1SQ' ) flag++;
if ( ver == '3.5.0E' ) flag++;
if ( ver == '3.5.1E' ) flag++;
if ( ver == '3.5.2E' ) flag++;
if ( ver == '3.5.3E' ) flag++;
if ( ver == '3.5.0S' ) flag++;
if ( ver == '3.5.1S' ) flag++;
if ( ver == '3.5.2S' ) flag++;
if ( ver == '3.5.1SQ' ) flag++;
if ( ver == '3.5.2SQ' ) flag++;
if ( ver == '3.5.0SQ' ) flag++;
if ( ver == '3.6.4E' ) flag++;
if ( ver == '3.6.0E' ) flag++;
if ( ver == '3.6.1E' ) flag++;
if ( ver == '3.6.2aE' ) flag++;
if ( ver == '3.6.2E' ) flag++;
if ( ver == '3.6.3E' ) flag++;
if ( ver == '3.6.0S' ) flag++;
if ( ver == '3.6.1S' ) flag++;
if ( ver == '3.6.2S' ) flag++;
if ( ver == '3.7.3E' ) flag++;
if ( ver == '3.7.0E' ) flag++;
if ( ver == '3.7.1E' ) flag++;
if ( ver == '3.7.2E' ) flag++;
if ( ver == '3.7.0S' ) flag++;
if ( ver == '3.7.0bS' ) flag++;
if ( ver == '3.7.0xaS' ) flag++;
if ( ver == '3.7.1S' ) flag++;
if ( ver == '3.7.1aS' ) flag++;
if ( ver == '3.7.2S' ) flag++;
if ( ver == '3.7.2tS' ) flag++;
if ( ver == '3.7.3S' ) flag++;
if ( ver == '3.7.4S' ) flag++;
if ( ver == '3.7.4aS' ) flag++;
if ( ver == '3.7.5S' ) flag++;
if ( ver == '3.7.6S' ) flag++;
if ( ver == '3.7.7S' ) flag++;
if ( ver == '3.8.0S' ) flag++;
if ( ver == '3.8.1S' ) flag++;
if ( ver == '3.8.2S' ) flag++;
if ( ver == '3.9.0S' ) flag++;
if ( ver == '3.9.0aS' ) flag++;
if ( ver == '3.9.1S' ) flag++;
if ( ver == '3.9.1aS' ) flag++;
if ( ver == '3.9.2S' ) flag++;
if ( ver == '3.10.0S' ) flag++;
if ( ver == '3.10.0aS' ) flag++;
if ( ver == '3.10.1S' ) flag++;
if ( ver == '3.10.1xbS' ) flag++;
if ( ver == '3.10.2S' ) flag++;
if ( ver == '3.10.2tS' ) flag++;
if ( ver == '3.10.3S' ) flag++;
if ( ver == '3.10.4S' ) flag++;
if ( ver == '3.10.5S' ) flag++;
if ( ver == '3.10.6S' ) flag++;
if ( ver == '3.10.7S' ) flag++;
if ( ver == '3.10.01S' ) flag++;
if ( ver == '3.11.0S' ) flag++;
if ( ver == '3.11.1S' ) flag++;
if ( ver == '3.11.2S' ) flag++;
if ( ver == '3.11.3S' ) flag++;
if ( ver == '3.11.4S' ) flag++;
if ( ver == '3.12.0S' ) flag++;
if ( ver == '3.12.0aS' ) flag++;
if ( ver == '3.12.1S' ) flag++;
if ( ver == '3.12.4S' ) flag++;
if ( ver == '3.12.2S' ) flag++;
if ( ver == '3.12.3S' ) flag++;
if ( ver == '3.13.2aS' ) flag++;
if ( ver == '3.13.5S' ) flag++;
if ( ver == '3.13.0S' ) flag++;
if ( ver == '3.13.0aS' ) flag++;
if ( ver == '3.13.1S' ) flag++;
if ( ver == '3.13.2S' ) flag++;
if ( ver == '3.13.3S' ) flag++;
if ( ver == '3.13.4S' ) flag++;
if ( ver == '3.14.0S' ) flag++;
if ( ver == '3.14.1S' ) flag++;
if ( ver == '3.14.2S' ) flag++;
if ( ver == '3.14.3S' ) flag++;
if ( ver == '3.14.4S' ) flag++;
if ( ver == '3.15.1cS' ) flag++;
if ( ver == '3.15.3S' ) flag++;
if ( ver == '3.15.0S' ) flag++;
if ( ver == '3.15.1S' ) flag++;
if ( ver == '3.15.2S' ) flag++;
if ( ver == '3.17.0S' ) flag++;
if ( ver == '3.17.1S' ) flag++;
if ( ver == '3.16.0S' ) flag++;
if ( ver == '3.16.0cS' ) flag++;
if ( ver == '3.16.1S' ) flag++;
if ( ver == '3.16.1aS' ) flag++;
if ( ver == '3.16.2S' ) flag++;
if ( ver == '3.16.2aS' ) flag++;

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
    exit(0);
  }
  else security_warning(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
