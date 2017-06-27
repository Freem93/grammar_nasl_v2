#TRUSTED 496d8c15aa84f44d467be9d1593bc060e6ecc92c3d2e9ff883b0e83359d41a6e6c2662de17a2b9376c050139244720d397830386e2f1cf8a52df2d4a4338d9bf7e47e09fe7f4d4a26a33bee6db30d48c714cfe9d74e92f8e22a68c60a3d6987ff58a22cc94c0c43ae1dc95159f2eb24fc9f786221c99be97dedbb9e2932da217fc68ee8727b1fc11839deee13b1928ae51d846045a721b2abcd96f25a5ee0590f9ddcc969ad6d51b874228860571137589d27cd288e2c368b3ba555d5405295ddbeaefa2065d10333af1700cac1ac197c095164b24014c529c02748cc1f2ec3ab4303f0de307f961ec508983aa6ee3acfe1b0ff4444c83a5c4cb7afadf3deb27290c11f086e16a8cba598e9502cca2a940c4611a8c2a4d222ea75fc46bde71f3f6723dde637d298a6d2a5aadb1928cf4f510d329a74c738e0406eb374d0c0172d8b07df57d2061330875e9b32022cf2ddad195cbb6fb3e0800febb4f68fb7685a3983a2e067a1e00e140a9752b3e1dd8fa12bd1c492280183392d368e8056f76cb920e6918df1a32db0b9ee2d15e7ffa4bb5fed5c4d06a1c1ebe51db9b19398aaa69202a66dce56e069018b420e35068ff76f4140886972e8f49e5fe2a7bf45e9ac3bc916e0b82e9a72c6bc91698e26b6893e7dbb86726932f00a6e22e432ecde3887d18b6d62dc00979a086cb3cec0c60e3258f6991d57f50c5e9b352f6dbfa
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69194);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2013-0149", "CVE-2013-7313");
  script_bugtraq_id(65169);
  script_osvdb_id(95909);
  script_xref(name:"CERT", value:"229804");
  script_xref(name:"JSA", value:"JSA10582");

  script_name(english:"Juniper Junos OSPF Protocol Vulnerability (JSA10582)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device has a flaw in its OSPF implementation. A rogue router in
the same autonomous system (AS) could exploit this to control the
routing tables of all other routers in the AS.

Note that this issue does not affect device with one of the following
configurations :

  - Interfaces not configured for OSPF

  - Passive OSPF interfaces

  - OSPF configurations that use MD5 authentication

  - OSPF interfaces that block external parties from sending
    OSPF link-state update packets");
  script_set_attribute(attribute:"see_also", value:"http://crypto.stanford.edu/seclab/sem-12-13/nakibly.html");
  script_set_attribute(attribute:"see_also", value:"https://www.blackhat.com/us-13/archives.html#Nakibly");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10582");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10582.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (compare_build_dates(build_date, '2013-07-25') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['10.4'] = '10.4R15';
fixes['11.4'] = '11.4R8';
fixes['12.1X44'] = '12.1X44-D15';
fixes['12.1X45'] = '12.1X45-D10';
fixes['12.1'] = '12.1R7';
fixes['12.2'] = '12.2R5';
fixes['12.3'] = '12.3R3';
fixes['13.1'] = '13.1R3';
fixes['13.2X50'] = '13.2X50-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check if OSPF is enabled without MD5 authentication / passive mode
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols ospf .* (authentication md5|passive) ";
  if (junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, "affected because OSPF is not enabled or OSPF is enabled with MD5 authentication or in passive mode");
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
