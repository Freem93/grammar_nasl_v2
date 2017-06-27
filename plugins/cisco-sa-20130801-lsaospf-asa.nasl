#TRUSTED 325a046f01990e144a1732583222251b101c8ce82569bef1208c13cdc1dad370d96f0d9ff49469f6ab51a3fc2d128ef67e85e164f12efd44ea0370f0265f64527ff6594c24eb387c2c3ddbacb9ebd15279acbaa9f81b371f5b12444bd454152ffb52e27ac4f6b3ada56a409cba2dad7e74e5ca4e0c2d46085bbc6a725c022e3802b77ab3bb7e64f0938fd5165b6fb82c0816d20d977970a55d7a88ed99688b94534f0a18addda2a176cf2d1bef869c30e0733d2ed0caa07848098509f3d8509c4ec1af4fe9d75654fba6e56be48d19799e13c70bbdafaf40d2fc86445f70f2cabaa1e2a3e79b41d9ac4dd47748033a81c2d2977f18d6ecc0bd68958b7ca310a16f90de53088a3de87e8b9709c8d8b90b9a9422eea34ab658ab233e0bef982631ae0d6454504752e1a50b17352c8152329bf912cea6e5c43f8f56ec9429e7fa64180252d7e740ed655bbba5fd0c7c22dec5883ae2a6f71243354b2d0814af529d97a903862e631ce09577b44d15dcb292be5950f81f29812bf616d140a483075b64a84e0a2d1bdf007d158c0e0a5d34f31be3bd20dfb4a042be55acafff2a301d45231acbc07ff934d3253edce980105c08f3ff01623146b51f4521c4720d2fca3f72fda59b6419dd8bb6ae1bc6260195d10a8aee62d668d2325944d0f37e84958f1dca89a1f761a17e193c1a58fe390bdd77e61066e851987697bbef68b83dba
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69376);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/02/28");

  script_cve_id("CVE-2013-0149");
  script_bugtraq_id(61566);
  script_osvdb_id(95909);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug34469");
  script_xref(name:"IAVA", value:"2013-A-0157");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130801-lsaospf");

  script_name(english:"OSPF LSA Manipulation Vulnerability in Cisco ASA (cisco-sa-20130801-lsaospf)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco ASA device is affected by a vulnerability
involving the Open Shortest Path First (OSPF) Routing Protocol Link
State Advertisement (LSA) database.  This vulnerability could be
exploited by injecting specially crafted OSPF packets.  Successful
exploitation could allow an unauthenticated attacker to manipulate
or disrupt the flow of network traffic through the device.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130801-lsaospf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58c1354a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130801-lsaospf.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_5500");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/16");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
report_extras = "";

asa = get_kb_item_or_exit('Host/Cisco/ASA');
ver = extract_asa_version(asa);
if (isnull(ver))
  audit(AUDIT_FN_FAIL, 'extract_asa_version');

fixed_ver = "";

if (
  ver =~ "^7\." ||
  ver =~ "^8\.0[^0-9]" ||
  ver =~ "^8\.1[^0-9]" ||
  ver =~ "^8\.2[^0-9]" ||
  ver =~ "^8\.3[^0-9]")
{
  flag++;
  fixed_ver = "8.4(6)5";
}

if (
  ver =~ "^8\.4[^0-9]" &&
  check_asa_release(version:ver, patched:"8.4(6)5"))
{
  flag++;
  fixed_ver = "8.4(6)5";
}

if (
  ver =~ "^8\.5[^0-9]" ||
  ver =~ "^8\.6[^0-9]")
{
  flag++;
  fixed_ver = "9.0(3)";
}

if (
  ver =~ "^9\.0[^0-9]" &&
  check_asa_release(version:ver, patched:"9.0(3)"))
{
  flag++;
  fixed_ver = "9.0(3)";
}

if (
  ver =~ "^9\.1[^0-9]" &&
  check_asa_release(version:ver, patched:"9.1(2)5"))
{
  flag++;
  fixed_ver = "9.1(2)5";
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ospf_interface", "show ospf interface");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"line protocol is up", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
