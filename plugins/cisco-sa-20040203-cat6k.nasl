#TRUSTED 41b5f00c6d5d1b830df293dfffea93657af6a52ae06492130d5fc14a4da052dad938595aeb3df0a7fec8ca16a0f1dcab3295cab644ed4bb4f1a1c259d077898ecfd6d7b69c67918ac93d7d0ac8517e2446d5772874101a3b583c221925788915ad53a60102d0ef3b55a0df3f3d2f0cf1ce40d469d5d26b3d4ef5ae075e3272a52fc0138d15b6716a6bcba25c4f95bea75e787fb1148fb1f7a9095fc4938254b2ab633e992686e253ad504380484bff838cd79fe58b83e13f0509f1761d1903c083f4f25997d8a53d297225c456cd8c167ba7c443954a8ec8cf0ccf582eccf4c21936d2f3096177916838cb40c0a58b03be8d9205f80ce28154ac3c99140d8319efeec7da7e3637065f426e414f191b46eb0bd294e228d21900b6ecd0f0c241a7465ad4017717525c9ed1080a8bdf7b2d9f964fb717f6fd87e2341db498f09f6ec9ac868b597849cf16af5e61b44e89feea97260cd1a150059d5da5f8167ff9c0475196c489289910ed5e41951fb89d8a776066e2cf8be905f50d687ed9a55bfb104b35ac699c6e25568246202eb8895ebe2b4e905281ce25eb400d5e3fbc607e895aaacd57d37aef2843e9cde2972b382a3231c8076dc8d4332e14d95b7bf421882193b57f1513d67d7861b704b48ba325495f667d8d3104a2c2cff28f7ed688a66840c62f8e07da5069d74bf97a3cb7b1859b6aed324cedf55dfa684fcbe48f
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00801f3a8a.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48973);
 script_version("1.11");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2004-0244");
 script_bugtraq_id(9562);
 script_osvdb_id(3804);
 script_name(english:"Cisco 6000/6500/7600 Crafted Layer 2 Frame Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'A layer 2 frame (as defined in the Open System Interconnection
Reference Model) that is encapsulating a layer 3 packet (IP, IPX, etc.)
may cause Cisco 6000/6500/7600 series systems with Multilayer Switch
Feature Card 2 (MSFC2) that have a FlexWAN or Optical Services Module
(OSM) or that run 12.1(8b)E14 to freeze or reset, if the actual length
of this frame is inconsistent with the length of the encapsulated layer
3 packet.
This vulnerability may be exploited repeatedly causing a denial of
service.
This vulnerability has been addressed by the Cisco Bug IDs CSCdy15598
and CSCeb56052.
There is no workaround available. A software upgrade is needed to
address the vulnerability.');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20040203-cat6k
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?efcdea28");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00801f3a8a.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?b10c225d");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20040203-cat6k.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/03");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/02/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdy15598");
 script_xref(name:"CISCO-BUG-ID", value:"CSCeb56052");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20040203-cat6k");
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
report_extra = "";
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(8b)E15", "12.1(11b)E14", "12.1(13)E1", "12.1(13.5)E", "12.1(19)E") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2SY
if (check_release(version: version,
                  patched: make_list("12.2(14)SY") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2ZA
if (check_release(version: version,
                  patched: make_list("12.2(14)ZA") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_module", "show module");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"WS-X6182-2PA", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"OSM", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_warning(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
