#TRUSTED 1ef7ea445b37afebeaada3686022f6e08156295d58b7fd8ef5cc6a5ab7469473e203906e61408c4995aa7c77855eb631b9d0ffe337eb10f6b061be8a01a984f7a5cadf181a93a7a35b3bda4d87b15d9bf198542fb84f6e5637b5e086edf31141697c87f6c095a0b350bbca57e39c2b5769706597090ab45fa58ec533f58e4086f869b11a6c2810eabd829cdf133e8cfbf9a3e3c9c045a532c02a141804e4d7d86f30a5c7ef6a2ab477a5e5c65964c0edb7438a2328f7bce74d81d8c84fb42e18142a3e2a12977b095a77a67afcd8967fdf4f121b949dbf019bc803814e564e2b4811584ff42032269334a470fa31a424b36f58363d123d49c4de2417bc8adf5bd1a125e7247ee965b76584a65cca87a2dcb7debb9394c42a31baf078992e885ed74e9e8c092b91ae48c33f114ef0fe56e3f0b8779d8bfb29bcb68de8303c99afceefd1a08a4d10629fbd17499f889badcbdf7b331bb45e5fb2fba21120c15d989498352011645644c2709be6c51ee29671dd2d8c3f7481eff119008dbe8234b135f7efe4b7f19ef3f4cab1c634aef1d8bffa6d19980b6b3aaff0869935ae4947708a8c66dc68c59c04a20eac9b842fbedd6d1de495897148e894882096dffba3b3638907e5d0cdf46ca3bcfa83f8f7e017350201fce16ce17ef08a8428794e95c5182d5b422874a1a4cc675fb2272f51d32018551ae9c57f99f9243d45b7e39d
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080aea4c9.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49037);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2009-1168", "CVE-2009-2049");
 script_bugtraq_id(35860, 35862);
 script_osvdb_id(56704, 56705);
 script_name(english:"Cisco IOS Software Border Gateway Protocol 4-Byte Autonomous System Number Vulnerabilities - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Recent versions of Cisco IOS Software support RFC4893 ("BGP Support for
Four-octet AS Number Space") and contain two remote denial of service
(DoS) vulnerabilities when handling specific Border Gateway Protocol
(BGP) updates.
These vulnerabilities affect only devices running Cisco IOS Software
with support for four-octet AS number space (here after referred to as
4-byte AS number) and BGP routing configured.
The first vulnerability could cause an affected device to reload when
processing a BGP update that contains autonomous system (AS) path
segments made up of more than one thousand autonomous systems.
The second vulnerability could cause an affected device to reload when
the affected device processes a malformed BGP update that has been
crafted to trigger the issue.
Cisco has released free software updates to address these
vulnerabilities.
No workarounds are available for the first vulnerability.
A workaround is available for the second vulnerability.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46682303");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080aea4c9.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?c40e4bd6");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090729-bgp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(16);
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/29");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/07/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCsy86021");
 script_xref(name:"CISCO-BUG-ID", value:"CSCta33973");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090729-bgp");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(24)T1') flag++;
else if (version == '12.4(24)T') flag++;
else if (version == '12.4(24)GC1') flag++;
else if (version == '12.2(33)SXI1') flag++;
else if (version == '12.0(32)SY9') flag++;
else if (version == '12.0(32)SY8') flag++;
else if (version == '12.0(33)S3') flag++;
else if (version == '12.0(32)S13') flag++;
else if (version == '12.0(32)S12') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"router bgp ", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
