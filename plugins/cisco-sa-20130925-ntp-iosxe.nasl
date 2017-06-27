#TRUSTED a963ee6187f0ef8228c7ef4d91e4e53ef782747a78de880a9236590b57408bdf048281ad4bfa7ac0012bb87c7f612393cb2b6c94cdcd8586b2b6125e9a7d75a0dcb6077df64b13a1803bff49c4512007e4fdbb0e261ca2a0dea4d4fe9e91afe03758498293e8e3b9769236a4be854d83d6016c71bf93af4ab18bef7c8b4a4e247f8bbba8f7ebc728e7dd829f766c50f1afafee9228b3a0bcf4ea7bf69fd9cedc57278528c961d0e6e9ba83e7be85b4132674f324c360e674c14a4e38d1ff3b6ef00abd658bbb6fc696edf0c26b3b566c3ed089bbca48bbcdc12a09badd92a86fa07d27ccf90159a2a0f785013cf0029a26b806d3172b1f9e66a4a223c4a28dd35c881b11f019e600ee6660a90dfadbe4aeb48928bac06b78644d20210ffff6018a1b01ae0db2333d1204c06dd8ab4f9189d76c2648243cefdc95d56e932486f0e1fa8152763de28402c178d1ebc032dfca48fd716c9b215786011ab9fcedcfb790033870d644e4658f4ab2d2bc7134eca68568fc442ccacc801b9597cf570a0c4804abadb8d3410606e5dda2fcef5faa70c9f2399da5ce60c5e592a2d44223c15664318ecbc0de4457c6453b19f330c63035772d8bdfcaa2a67118306f928a0d02526e576d2b96887a72d1389ddda7a834aaf35e275120b7e9a25a83454a55592c49fd7010e91ba27ad9757aa30d196f24a0e335fa8989d4d2daba4951c2a939
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-ntp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70321);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/07/28");

  script_cve_id("CVE-2013-5472");
  script_bugtraq_id(62640);
  script_osvdb_id(97742);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc81226");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-ntp");

  script_name(english:"Cisco IOS XE Software Multicast Network Time Protocol Denial of Service Vulnerability (cisco-sa-20130925-ntp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the implementation of the Network Time Protocol
(NTP) feature in Cisco IOS XE Software allows an unauthenticated,
remote attacker to cause an affected device to reload, resulting in a
denial of service (DoS) condition. The vulnerability is due to
improper handling of multicast NTP packets that are sent to an
affected device encapsulated in a Multicast Source Discovery Protocol
(MSDP) Source-Active (SA) message from a configured MSDP peer. An
attacker can exploit this vulnerability by sending multicast NTP
packets to an affected device. Repeated exploitation can result in a
sustained DoS condition. Cisco has released free software updates that
address this vulnerability. A workaround is available to mitigate this
vulnerability."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-ntp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37c601ac");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco security advisory
cisco-sa-20130925-ntp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
if ( version =~ '^2\\.1([^0-9]|$)' ) flag++;
else if ( version =~ '^2\\.2([^0-9]|$)' ) flag++;
else if ( version =~ '^2\\.3([^0-9]|$)' ) flag++;
else if ( version =~ '^2\\.4([^0-9]|$)' ) flag++;
else if ( version =~ '^2\\.5([^0-9]|$)' ) flag++;
else if ( version =~ '^2\\.6([^0-9]|$)' ) flag++;
else if ( version =~ '^3\\.1(\\.[0-9]+)?S$' ) flag++;
else if ( version =~ '^3\\.1(\\.[0-9]+)?SG$' ) flag++;
else if ( version =~ '^3\\.2(\\.[0-9]+)?S$' ) flag++;
else if ( version =~ '^3\\.2(\\.[0-9]+)?SG$' ) flag++;
else if ( version =~ '^3\\.2(\\.[0-9]+)?XO$' ) flag++;
else if ( version =~ '^3\\.2(\\.[0-9]+)?SQ$' ) flag++;
else if (( version =~ '^3\\.3(\\.[0-9]+)?S$' ) && (cisco_gen_ver_compare(a:version,b:'3.3.0S') == -1)) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ntp multicast", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    if (flag)
    {
      buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_msdp_summary", "show ip msdp summary");
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ .* Up", multiline:TRUE, string:buf)) { flag = 1; }
      } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
    }
    else { flag = 0; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
