#TRUSTED 2484f7bca38e8d42b866269f6a9e8fe8ec7798ca4fbf67927a7ea2055263df9b660e43c53c3b694bde8f95ed0276b6ad74141d07a2f31efff71d20c7d9c2520f5eba1ed4028e7ce419ab6f031326fae781f20fe550891e66f26a3b1e04d575852a26e65fb3a2b0b11f09bf3c10cf29fcf527fef819853b55a0011bbf1ec1a35404c845d4d89b65356490462d8b99e809cbf200201c455386a35248867b2b6b1b3fdfacf67a5dafb15c5236598dbf1b42698fee2869719d36d07de6ad2031d0525d2335b80203d2c58de8e033c32e564fa38f4d339220205c3e1c7d1c5a1c49cdf93b25fd528dbfb30ba252154c0f1fb567c7f32c6190275884ac64b56ba92b778e1ec545b7338dfc25fcde55ab3c95308bc1824d370256fe4d30ebc4e3dd4bb462b019c2c3249fae85d2621e420c3088820321837029d0d1fcfef91ac4b77ca6d99f458bf854a1b1cd7ab1efd3f3feeb1341c82e8de44f2899d3dcc4906b09e2a15e5cc90cc9b321b13f3a664a07973e938c32e828355e5ff4826add6831b801eccc0f7172a00ddcee464b869a2b0341afcd79edbdb27a90e01035310e73ba84ef1a80fe1677e415f332c1b5e0ad8e622b9e9b59e346e44377d2aad49a6d20ca3870610be60f5c7ca827872bb0330a351f349b9974687e3ba93c86718de682a70a1f7ec42602831f0a7c569d63b5702c30b6b7fb4c31c8e1b7f70e528bc07662
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82588);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/08/02");

  script_cve_id("CVE-2015-0640");
  script_bugtraq_id(73337);
  script_osvdb_id(119941);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo25741");

  script_name(english:"Cisco IOS XE Fragmented Packet DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE software running on the remote device is affected by
a denial of service vulnerability in the high-speed logging (HSL)
feature due to improper processing of fragmented IP packets. An
unauthenticated, remote attacker, by sending a large number of
oversized packets, can exploit this to cause a device reload.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-iosxe#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30ea0b29");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuo25741");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

# Per Bug CSCuo25741
if (
  !(
    "ASR1k"    >< model ||
    "ISR4400"  >< model ||
    "CSR1000V" >< model
  )
) audit(AUDIT_HOST_NOT, "an affected model");

# Bug (converted) and CVRF
if (version == "3.10.0S") flag++;
if (version == "3.11.0S") flag++;

# CVRF
if (version == "3.10.0Sa") flag++;
if (version == "3.10.1S")  flag++;
if (version == "3.10.2S")  flag++;
if (version == "3.10.3S")  flag++;
if (version == "3.11.1S")  flag++;
if (version == "3.11.2S")  flag++;
if (version == "3.12.0S")  flag++;
if (version == "3.12.1S")  flag++;
if (version == "3.1.0S")   flag++;
if (version == "3.1.1S")   flag++;
if (version == "3.1.2S")   flag++;
if (version == "3.1.3S")   flag++;
if (version == "3.1.4S")   flag++;
if (version == "3.1.5S")   flag++;
if (version == "3.1.6S")   flag++;
if (version == "3.2.0S")   flag++;
if (version == "3.2.1S")   flag++;
if (version == "3.2.2S")   flag++;
if (version == "3.2.3S")   flag++;
if (version == "3.3.0S")   flag++;
if (version == "3.3.1S")   flag++;
if (version == "3.3.2S")   flag++;
if (version == "3.5.0S")   flag++;
if (version == "3.5.1S")   flag++;
if (version == "3.5.2S")   flag++;
if (version == "3.6.0S")   flag++;
if (version == "3.6.1S")   flag++;
if (version == "3.6.2S")   flag++;
if (version == "3.7.0S")   flag++;
if (version == "3.7.1S")   flag++;
if (version == "3.7.2S")   flag++;
if (version == "3.7.3S")   flag++;
if (version == "3.7.4S")   flag++;
if (version == "3.7.5S")   flag++;
if (version == "3.7.6S")   flag++;
if (version == "3.7.7S")   flag++;
if (version == "3.8.0S")   flag++;
if (version == "3.8.1S")   flag++;
if (version == "3.8.2S")   flag++;
if (version == "3.9.0S")   flag++;
if (version == "3.9.1S")   flag++;
if (version == "3.9.2S")   flag++;

# From SA (and not covered by Bug or CVRF)
if (version =~ "^2\.") flag++;
if (version =~ "^3\.4($|[^0-9])") flag++;

# Check NAT config
if (flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      (preg(multiline:TRUE, pattern:"^ip nat inside$", string:buf)) &&
      (preg(multiline:TRUE, pattern:"^ip nat outside$", string:buf)) &&
      (preg(multiline:TRUE, pattern:"^ip nat (inside|outside) source ", string:buf)) &&
      !(preg(multiline:TRUE, pattern:"^no ip nat ", string:buf))
    ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCuo25741' +
    '\n  Installed release : ' + version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
