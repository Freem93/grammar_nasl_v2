#TRUSTED 4b42a847411e0f9d947fd78fd03cf732d1b70522565aaae9cf75d521a9a4f24fcf5ff875fd3c9b9231b3e5a60c02e297f07cecf1db90d5dfec757b018491fc65d4f09cb76568949a2f4938eaa058a9ce79f4dbb398f699e4711d8fc90f5561e8fac810092deb63a779bae7a9b9c97e5c6149e4e85dd01234b1bdbe8647a9f0368b8481cc9ce61c117565cd43fba83a399945dae1cba59d41cf6e5005b9ea9dacd53cfc61d078c085fd17bbd100eacb9a781857c4480633f56d858289a55eaf8da95056c84722ebf72fe6511598ad08f14981253122fadf0620cd706cb413f129eb750ffec6c6a3e901e74c4b7f1d3cfec658b1eb038522cf524cb1b856c31a92de2289b307c398fb084e5b7e5b90500b1e0a2d480029e80f9c8a7c5e3acb90bb16cf4f4fabc5a0077a1fd1388229a07628b802506e114c4922055c62a648098d04676837bf8aa6c920821feb23f1602dffa4ca281201dc5df029af517e7a7480460ab2804a4814b7d241d266e6d4d036dc3ebbe92d8821c49693a52bb8196729a090333953e62b79ba6b3c92d8f8c91964f03570d9646dc9be69eb652e83573ed79f23152f72cc9dad3869a3498720a593d73bff8056bcfe42d335a6643ed9128d3be3155cce9bc69883cc918369fce143ba4cc6b03797cb572fba9ca2e740a33d503d442415b1423e8b17ec15c9e066fdcec102f108fcd8cbd60081503554d8
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20110928-ipsla.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(56315);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2011-3272");
  script_bugtraq_id(49823);
  script_osvdb_id(76069);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtk67073");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110928-ipsla");

  script_name(english:"Cisco IOS Software IP Service Level Agreement Vulnerability (cisco-sa-20110928-ipsla)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco IOS IP Service Level Agreement (IP SLA) feature contains a
denial of service (DoS) vulnerability. The vulnerability is triggered
when malformed UDP packets are sent to a vulnerable device. The
vulnerable UDP port numbers depend on the device configuration.
Default ports are not used for the vulnerable UDP IP SLA operation or
for the UDP responder ports. Cisco has released free software updates
that address this vulnerability."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20110928-ipsla
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c91b30f3"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20110928-ipsla."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '15.1(1)S' ) flag++;
if ( version == '15.1(1)S1' ) flag++;
if ( version == '15.1(1)S2' ) flag++;
if ( version == '15.1(1)SA1' ) flag++;
if ( version == '15.1(1)SA2' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)T1' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)XB' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if ( version == '15.1(1)XB2' ) flag++;
if ( version == '15.1(1)XB3' ) flag++;
if ( version == '15.1(2)GC' ) flag++;
if ( version == '15.1(2)GC1' ) flag++;
if ( version == '15.1(2)T' ) flag++;
if ( version == '15.1(2)T0a' ) flag++;
if ( version == '15.1(2)T1' ) flag++;
if ( version == '15.1(2)T2' ) flag++;
if ( version == '15.1(2)T2a' ) flag++;
if ( version == '15.1(2)T3' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sla_responder", "show ip sla responder");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Enable", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sla_configuration", "show ip sla configuration");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"operation[^\r\n]*udp-echo", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"operation[^\r\n]*udp-jitter", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
