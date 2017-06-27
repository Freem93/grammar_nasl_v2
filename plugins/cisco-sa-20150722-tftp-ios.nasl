#TRUSTED 77b0c6fa921a76129007e9ee75b2ec7f6de7586e2cbb87e881f52141e35f6d2e0ad964bbc2b0742bc003ad937e0d5dedca8ab9440b091a2783d1263c4ea8aeca664d713cedb95db0ba2644c28ec188a030d38bc3ad14b60c1dbcea98b168da1f0008b6b3f43ce08a8fc03ccf65c4eacb4990774cad82dd5d7c7c56c33bb0b5d1aac7a7d370b9008ea05853d75a8d84a8e76e90b066e2bd0c5e5badd65bb983112d7a8f2f5655e49f0affb2e1674806ba9aeaa3cf23072ef378124ff9e15dfd6bbeb2ce14f54ef5d01b4e8bcf980948d933307c63c7cab4297e6430ec1f63838897d0e2d3ec522da3bd7aa38d90e31ec2ad6cf1b81aa4846e986066859b7811ae70db3df77e20257c2db3e1fc85f5c1396544f2a3749536e5a1be8d5b25e5830322090f56cb1f59d0abe670cec0c469be031f2075c672a712b5c66ace7e95227820ccc08c7e41f3295ec2daccd0d4a6c1ed8b32cfca206928813cbb4764c87ba58292067e697b637a7b233f50b8f09fdbdc11d335ce7ac95d7e876a1a58daebc2530c6402306ae36f26dafc30d69a247b658e66615175c884cabe68c42c52c741aa790c3806b44949c7c14fb392f76e380017c9ff6c21fed0121094d0786c290a1c9d9561357db96eaea020d75b3cc9b5a24d4366d161a29577de79eec4880635d651555cf0811ebc9f167c08c8c25203eed752c6ec0eed92c6945f4a466c58e0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85124);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/10/12");

  script_cve_id("CVE-2015-0681");
  script_bugtraq_id(75995);
  script_osvdb_id(125122);
  script_xref(name:"CISCO-BUG-ID", value:"CSCts66733");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150722-tftp");

  script_name(english:"Cisco IOS Software TFTP DoS (cisco-sa-20150722-tftp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the TFTP server functionality due to incorrect management of memory
when handling TFTP requests. A remote, unauthenticated attacker can
exploit this by sending a large amount of TFTP requests to cause the
remote device to reload or hang, resulting in a denial of service
condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150722-tftp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18ef700f");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCts66733");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20150722-tftp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/30");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

app = "Cisco IOS";
cbi = "CSCts66733";
fixed_ver = NULL;

if (
  ver == "12.2(32.8.11)SX507" || # Bug report
  ver == "12.2(44)SQ1" || # Vulnerability Alert
  ver == "12.2(50)SY" ||
  ver == "12.2(50)SY1" ||
  ver == "12.2(50)SY2" ||
  ver == "12.2(50)SY3" ||
  ver == "12.2(50)SY4" ||
  ver == "12.2(33)XN" ||
  ver == "12.2(33)XN1" ||
  ver == "12.4(24)GC1" ||
  ver == "12.4(24)GC3" ||
  ver == "12.4(24)GC3a" ||
  ver == "12.4(25e)JAM1" ||
  ver == "12.4(25e)JAO5m" ||
  ver == "12.4(23)JY" ||
  ver == "12.4(24)T" ||
  ver == "15.0(2)ED1" ||
  ver == "15.0(2)EY3" ||
  ver == "15.0(1)M1" ||
  ver == "15.0(1)M4" ||
  ver == "15.0(1)SY" ||
  ver == "15.0(1)XA" ||
  ver == "15.0(1)XA2" ||
  ver == "15.0(1)XA3" ||
  ver == "15.0(1)XA4" ||
  ver == "15.0(1)XA5" ||
  ver == "15.1(3)SVF4a" ||
  ver == "15.1(3)SVF4b" ||
  ver == "15.1(3)SVG3b" ||
  ver == "15.1(3)SVH2" ||
  ver == "15.1(3)SVI" ||
  ver == "15.1(3)SVI1" ||
  ver == "15.1(1)T" ||
  ver == "15.1(1)T1" ||
  ver == "15.1(1)T2" ||
  ver == "15.1(2)T" ||
  ver == "15.1(2)T0a" ||
  ver == "15.1(2)T1" ||
  ver == "15.1(2)T2" ||
  ver == "15.1(2)T2a" ||
  ver == "15.1(3)T" ||
  ver == "15.2(2)JB1" ||
  ver == "15.2(1)SC1a" ||
  ver == "15.2(1)SC2" ||
  ver == "15.2(1)SD6a" ||
  ver == "15.2(1)SD8" ||
  ver == "15.2(1)S2" || # IOS-XE to IOS Mapping using Internet resources
  ver == "15.2(1)S1" ||
  ver == "15.2(1)S" ||
  ver == "15.1(3)S6" ||
  ver == "15.1(3)S5" ||
  ver == "15.1(3)S4" ||
  ver == "15.1(3)S3" ||
  ver == "15.1(3)S2" ||
  ver == "15.1(3)S1" ||
  ver == "15.1(3)S0a" ||
  ver == "15.1(3)S" ||
  ver == "15.1(2)S2" ||
  ver == "15.1(2)S1" ||
  ver == "15.1(2)S" ||
  ver == "15.1(1)S2" ||
  ver == "15.1(1)S1" ||
  ver == "15.1(1)S" ||
  ver == "15.0(1)S4a" ||
  ver == "15.0(1)S4" ||
  ver == "15.0(1)S3" ||
  ver == "15.0(1)S2" ||
  ver == "15.0(1)S1" ||
  ver == "15.0(1)S" ||
  ver == "12.2(33)XNF2" ||
  ver == "12.2(33)XNF1" ||
  ver == "12.2(33)XNF" ||
  ver == "12.2(33)XNE2" ||
  ver == "12.2(33)XNE1" ||
  ver == "12.2(33)XNE" ||
  ver == "15.0(1)EX" || # IOS-XE to IOS mapping using info in cisco_ios_xe_version.nasl
  ver == "15.0(1)EX1" ||
  ver == "15.0(1)EX2" ||
  ver == "15.0(1)EX3" ||
  ver == "15.0(1)XO" ||
  ver == "15.0(1)XO1" ||
  ver == "15.0(2)SG" ||
  ver == "15.0(2)SG1" ||
  ver == "15.0(2)XO" ||
  ver == "15.1(1)SG" ||
  ver == "15.1(1)SG1" ||
  ver == "15.2(1)S1" ||
  ver == "15.2(1)S2" ||
  # Added due to VULN-81062
  ver == "122-55.SE10" ||
  ver == "122-33.SXI14" ||
  ver == "15.0(2)SE7" ||
  ver == "15.1(4)M10" ||
  ver == "15.0(2)SG10" ||
  # Added due to VULN-81062-2
  ver == "12.2(55)SE10" ||
  ver == "12.2(33)SXI14"
)
  fixed_ver = "Refer to vendor.";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);

flag     = TRUE;
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;
  # TFTP Check
  #  Router#show running-config | include ^tftp-server
  #  tftp-server flash:c2800nm-adventerprisek9-mz.124-1
  #  tftp-server flash:
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"tftp-server flash:", string:buf))
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}
else override = TRUE;

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because TFTP is not enabled");

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
