#TRUSTED 6492d1709dcbf50850421824cb0fb0ad67850842dbbb773b4f24520a3c0c0d3b84d7e5649fe87a8df09542ad0b111a3f3e40c7b3c8ab9e6984d2339eb9efbf54e505ca7596809c44f3f85fae60e7e36b3eb8c506b48c10e912624767d8dc3f55b074ae91b94f008d93f14cd2075920526b07c076727115fd2048ae6130d081f0ad8acbf0e383bd194decaa464538e6772dc54d7b5787d6705a1f61037b11344931cf9f2420425c5ef445bc0375e961c28cf2e39f7b345483c62be651fc5cbc55b9021a8f324a0fd29242a7a06c3b04a0e458d8275e1998c3c8898c0e08369aa2e07dea2160710c7fed725dcd265a7aa280937a0461f3bd7ea7f2ede79ed72029334cce2df5211352c891a78178c30edf72ff232fbc649893983dee64b56f96ec87fd66b42ae87985e413e09cdd5bb40bb83d4621cc21bdad2d6cfc87ec22e276a2dcfc1335c5074401955169154dc3dde2fed9ad6033d21e80ec6c0252f5de4347a63d990e6978769c9bef6c1ecbbc5d7fe5a219778ace9bdc2dba56f5e70e115b5a39bffe1f443adc58fef608447a61378ea979fe783aab1f1effe9a39b6b6132d1f63f14f9a3634f1dc0ee9be615c63c8aca24aff64cea9802d9a1d2e90791c354a97846a3495891e9ec688cc8737aa028508cab9f0ee8eeb1096f63c646f192df9b84b6daba3c380d154a14158e8da9211108f27619bcec63bf6089d49a45
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00807f4139.shtml

include("compat.inc");

if (description)
{
 script_id(49002);
 script_version("1.12");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");

 script_cve_id("CVE-2007-1257");
 script_bugtraq_id(22751);
 script_osvdb_id(33066);
 script_xref(name:"CERT", value:"472412");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsd75273");
 script_xref(name:"CISCO-BUG-ID", value:"CSCse39848");
 script_xref(name:"CISCO-BUG-ID", value:"CSCse52951");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20070228-nam");

 script_name(english:"Cisco Catalyst 6000, 6500 Series and Cisco 7600 Series NAM (Network Analysis Module) Vulnerability");
 script_summary(english:"Uses SNMP to determine if a flaw is present");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"Cisco Catalyst 6000, 6500 series and Cisco 7600 series that have a
Network Analysis Module installed are affected by a vulnerability, which
could allow an attacker to gain complete control of the system.  Only
Cisco Catalyst systems that have a NAM on them are affected.  This
vulnerability affects systems that run Internetwork Operating System
(IOS) or Catalyst Operating System (CatOS).

Cisco has made free software available to address this vulnerability
for affected customers.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?519fd09c");
 script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-20070228-nam.html");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20070228-nam.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/28");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/02/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
 script_end_attributes();

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

model = get_kb_item("CISCO/model");
if (model)
{
  if (
    model != "ciscoCat6000" &&
    model !~ "cat600\d+" &&
    model != "cat6500FirewallSm" &&
    model != "catalyst65xxVirtualSwitch" &&
    model != "catalyst6kSup720" &&
    model != "ciscoNMAONWS" &&
    model != "ciscoWSC6509neba" &&
    model != "ciscoWSC6509ve" &&
    model != "ciscoWsSvcFwm1sc" &&
    model != "ciscoWsSvcFwm1sy" &&
    model !~ "cisco76\d+"
  ) audit(AUDIT_HOST_NOT, "affected");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS/Model");
  if (model !~ "6[05][0-9][0-9]" && model !~ "76[0-9][0-9]") audit(AUDIT_HOST_NOT, "affected");
}


# Affected: 12.1E
if (check_release(version:version, patched:make_list("12.1(26)E8", "12.1(27b)E1")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.1EX
else if (check_release(version:version, patched:make_list("12.1(12c)EX", "12.1(13)EX")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2EU
else if (deprecated_version(version, "12.2EU"))
{
  report_extra = '\n' + 'Migrate to 12.2(25)EWA7 or later.\n';
  flag++;
}
# Affected: 12.2EW
else if (deprecated_version(version, "12.2EW"))
{
  report_extra = '\n' + 'Migrate to 12.2(25)EWA7 or later.\n';
  flag++;
}
# Affected: 12.2EWA
else if (check_release(version:version, patched:make_list("12.2(25)EWA7")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2IXA
else if (deprecated_version(version, "12.2IXA"))
{
  report_extra = '\n' + 'Migrate to 12.2(18)IXB2or later.\n';
  flag++;
}
# Affected: 12.2IXB
else if (check_release(version:version, patched:make_list("12.2(18)IXB2")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2S
else if (check_release(version:version, patched:make_list("12.2(14)S3", "12.2(18)S5", "12.2(20)S")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2SG
else if (check_release(version:version, patched:make_list("12.2(25)SG1")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2SGA
else if (check_release(version:version, patched:make_list("12.2(31)SGA1")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2SRA
else if (check_release(version:version, patched:make_list("12.2(33)SRA2")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2SX
else if (deprecated_version(version, "12.2SX"))
{
  report_extra = '\n' + 'Migrate to 12.2(18)SXD7a or later.\n';
  flag++;
}
# Affected: 12.2SXA
else if (deprecated_version(version, "12.2SXA"))
{
  report_extra = '\n' + 'Migrate to 12.2(18)SXD7a or later.\n';
  flag++;
}
# Affected: 12.2SXB
else if (deprecated_version(version, "12.2SXB"))
{
  report_extra = '\n' + 'Migrate to 12.2(18)SXD7a or later.\n';
  flag++;
}
# Affected: 12.2SXD
else if (check_release(version:version, patched:make_list("12.2(18)SXD7a")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2SXE
else if (check_release(version:version, patched:make_list("12.2(18)SXE6a")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2SXF
else if (check_release(version:version, patched:make_list("12.2(18)SXF5")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2SY
else if (deprecated_version(version, "12.2SY"))
{
  report_extra = '\n' + 'Migrate to 12.2(18)SXD7a or later.\n';
  flag++;
}
# Affected: 12.2ZA
else if (deprecated_version(version, "12.2ZA"))
{
  report_extra = '\n' + 'Migrate to 12.2(18)SXD7a or later.\n';
  flag++;
}
# Affected: 12.2ZU
else if (check_release(version:version, patched:make_list("12.2(18)ZU1")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}


if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_module", "show module");
    if (check_cisco_result(buf))
    {
      if (egrep(pattern:"[ \t]+(WS-SVC-NAM-1|WS-SVC-NAM-2|WS-X6380-NAM)([^0-9]|$)", string:buf)) flag = 1;
    }
    else if (cisco_needs_enable(buf))
    {
      flag = 1;
      override = 1;
    }
  }
}


if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
