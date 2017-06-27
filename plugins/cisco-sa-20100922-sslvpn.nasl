#TRUSTED 6f5956cf9de765dc0d3fa3fd9b6f62bd187b63b34f07897ff52d8201f1391975acef5f4b0cd43aa3e0dd33242d52df1d49dc56cba4ac6474c6026f813a44395be4e019373d257a24fdf5358ee1436c4465d6b745b70818f9cffbde416030d3aea9fb71ed6610482160ae6b75cd30a92e838c83b7114b95919edee22567e80e79649e3180da7a54dafdce03c8ed2142a60da00a7e4992752071ab12a0aad3f7332b087fba2d2110ceb5ccd3a0f7d0285868177567bd062afe8d9ebccccaec13f2ad56cde0f893152367937fb2b507f9e2e2034cb63797bae25fcb4e9b653e4f7988723b88ab93f09555b687f97dd7db2667337ab7364e36bf5f512243dbd13176d8d28f1a7ac83160acdc2092ca6454b45728d59f9a17176b16460fe36b657158f63dff47218bc7f87c5cf086f97b6671ebb5cf42fe049ac911bde581cbdc6c3d2b26bc80c793381fa7f7ea689634b4f0b389e9fb5b83a040cba042ba5b42a087c9daac50272c85da4ae539c2399b21ea1ee7b5159b99ffe628a02283604b5144faa295a1ca814d477183a8961db1d3e50f68b97a33f76e58160d5364307783aa6ea58b3a8a2a9e22ef999f6fc5e2cc0c1f534b9e03fdf7edd82a6b31fc7736a1d38a71af4e8b73e0a1da506d00a3913342e6d79afeae4c0f976303de280c1426d29869f43b1ce3af4bd70fab5d422a70dc6cbb3e6d6638a8fb11862d1b98e9c3
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20100922-sslvpn.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(17785);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2010-2836");
  script_bugtraq_id(43390);
  script_osvdb_id(68202);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtg21685");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100922-sslvpn");

  script_name(english:"Cisco IOS SSL VPN Vulnerability (cisco-sa-20100922-sslvpn)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco IOS Software contains a vulnerability when the Cisco IOS SSL VPN
feature is configured with an HTTP redirect. Exploitation could allow
a remote, unauthenticated user to cause a memory leak on the affected
devices, that could result in a memory exhaustion condition that may
cause device reloads, the inability to service new TCP connections,
and other denial of service (DoS) conditions. Cisco has released free
software updates that address this vulnerability. There is a
workaround to mitigate this vulnerability."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20100922-sslvpn
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61c2aff8"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20100922-sslvpn."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if ( version == '12.4(15)T13' ) flag++;
if ( version == '12.4(20)T5' ) flag++;
if ( version == '12.4(20)T5a' ) flag++;
if ( version == '12.4(22)T5' ) flag++;
if ( version == '12.4(24)T2' ) flag++;
if ( version == '12.4(24)T3' ) flag++;
if ( version == '15.0(1)M' ) flag++;
if ( version == '15.0(1)M1' ) flag++;
if ( version == '15.0(1)M2' ) flag++;
if ( version == '15.1(1)T' ) flag++;
if ( version == '15.1(1)XB1' ) flag++;
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"\s+http-redirect\s+port.*", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"webvpn", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      m = eregmatch(pattern:"webvpn gateway([^!]+)!", string:buf);
      if ( (!isnull(m)) && ("inservice" >< m[1]) ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
