#TRUSTED 24808d277d3aa89a2ec01d5299c3e16500e9bd6d8f7a28091594f2ed72ff93e516ffd5e472143d30a76a039ae8ee3b4a7ffd6748958814baba90ce250cf74df9810ee98cec33ed0ebed61c5cf17ad00d9bbf63632fc175174022f0b1f0a9172deb278705e639fbc8194ba59f9f4b674c855c52ab07730f88a3231d3184db479c31669553eb53ce6dd2d93e6c3fe1706923194e729a3b05b54d752876ad43dff0a6ae643e57615fa0b08da07e929f35b53608fc143fa63a1573bb601893d07fd5663ed33dd0e066e82cf471c5934d98d74038e9bdd3b41712dbf396850b5b6f15cf6000cf8f9217019997a039dda511a3ca723018031f1b64072e24caba928daa01bfddbe35f5d702a5f96b2f478294ea8e5aab57dd467f1dbd4457edf15ec06c4ef1cb2ce0420a2be21d679a9d29a84b8bdf412c2eb01e7196eb0eb2e60d2261ac6e9bb4fbee7c1fffa65382fd72058e5e0542e4fc70babb206785335a30aad9b5552f3d2f90ec925e3549bbf13aacf367b6f81f8a5837a8c887fcabe5850d6974681ef0b446c8fcc024c8202e5e336d50381bcd21c2a0d03551a1aaf30581abd3534d12b1e10826f575b78ca38d8442b7719102a065ba58b023e86d66791d3de24f0dd03cc4cba9d4dac35f5ea93772d041ec3e468758c904b6dd8f719dbae71f3daed8d39ff9bfd492c1675f15dd78e38cb09b12289d6db178b659fedcc770
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69378);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/02/28");

  script_cve_id("CVE-2013-0149");
  script_bugtraq_id(61566);
  script_osvdb_id(95909);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug34485");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130801-lsaospf");

  script_name(english:"OSPF LSA Manipulation Vulnerability in Cisco IOS XE (cisco-sa-20130801-lsaospf)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is affected by a vulnerability
involving the Open Shortest Path First (OSPF) Routing Protocol Link
State Advertisement (LSA) database. A remote, unauthenticated attacker
can exploit this vulnerability, via specially crafted OSPF packets, to
manipulate or disrupt the flow of network traffic through the device.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130801-lsaospf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58c1354a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco security advisory
cisco-sa-20130801-lsaospf.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/16");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

#
# @param fix     The second version string.
# @param ver     The first version string.
# @param strip   A character/string which should be removed
#
# @return -1 if ver < fix, 0 if ver == fix, or 1 if ver > fix.
##
function ver_cmp(fix, ver, strip)
{
  local_var ffield, vfield, flen, vlen, len, i;

  # strip out any desired characters before the comparison
  if (strip)
  {
    ver = str_replace(string:ver, find:strip, replace:'');
    fix = str_replace(string:fix, find:strip, replace:'');
  }
  # replace ( and ) with dots to make comparisons more accurate
  ver = ereg_replace(pattern:'[()]', replace:".", string:ver);
  fix = ereg_replace(pattern:'[()]', replace:".", string:fix);
  # Break apart the version strings into numeric fields.
  ver = split(ver, sep:'.', keep:FALSE);
  fix = split(fix, sep:'.', keep:FALSE);

  vlen = max_index(ver);
  flen = max_index(fix);
  len = vlen;
  if (flen > len) len = flen;
  # Compare each pair of fields in the version strings.
  for (i = 0; i < len; i++)
  {
    if (i >= vlen) vfield = 0;
    else vfield = ver[i];
    if (i >= flen) ffield = 0;
    else ffield = fix[i];

    if ( (vfield =~ "^\d+$") && (ffield =~ "^\d+$") )
    {
      vfield = int(ver[i]);
      ffield = int(fix[i]);
    }
    if (vfield < ffield) return -1;
    if (vfield > ffield) return 1;
  }
  return 0;
}

flag = 0;
override = 0;
report_extras = "";
fixed_ver = "";

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

if (version =~ "^2(\.[0-9]+)?") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.1(\.[0-9]+)?S$") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.1(\.[0-9]+)?SG$") {fixed_ver = "3.2.7SG" ; flag++; }
else if (version =~ "^3\.2(\.[0-9]+)?S$") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.2(\.[0-9]+)?SE$")
{
  if (ver_cmp(ver:version, fix:"3.2.2SE", strip:"SE") < 0)
  {
    fixed_ver = "3.2.2SE";
    flag++;
  }
}
else if (version =~ "^3\.2(\.[0-9]+)?SG$")
{
  if (ver_cmp(ver:version, fix:"3.2.7SG", strip:"SG") < 0)
  {
    fixed_ver = "3.2.7SG";
    flag++;
  }
}
else if (version =~ "^3\.2(\.[0-9]+)?SQ$") {fixed_ver = "3.3.0SQ" ; flag++; }
else if (version =~ "^3\.2(\.[0-9]+)?XO$") {fixed_ver = "Refer to the Obtaining Fixed Software section of the Cisco advisory." ; flag++; }
else if (version =~ "^3\.3(\.[0-9]+)?S$") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.3(\.[0-9]+)?SG$") {fixed_ver = "3.4.1SG" ; flag++; }
else if (version =~ "^3\.4(\.[0-9]+)?S$") {fixed_ver = "Refer to the Obtaining Fixed Software section of the Cisco advisory." ; flag++; }
else if (version =~ "^3\.4(\.[0-9]+)?SG$")
{
  if (ver_cmp(ver:version, fix:"3.4.1SG", strip:"SG") < 0)
  {
    fixed_ver = "3.4.1SG";
    flag++;
  }
}
else if (version =~ "^3\.5(\.[0-9]+)?S$") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.6(\.[0-9]+)?S$") {fixed_ver = "3.8.2S" ; flag++; }
else if (version =~ "^3\.7(\.[0-9]+)?S$") {fixed_ver = "Refer to the Obtaining Fixed Software section of the Cisco advisory." ; flag++; }
else if (version =~ "^3\.8(\.[0-9]+)?S$")
{
  if (ver_cmp(ver:version, fix:"3.8.2S", strip:"S") < 0)
  {
    fixed_ver = "3.8.2S";
    flag++;
  }
}
else if (version =~ "^3\.9(\.[0-9]+)?S$")
{
  if (ver_cmp(ver:version, fix:"3.9.1S", strip:"S") < 0)
  {
    fixed_ver = "3.9.1S";
    flag++;
  }
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ospf_interface", "show ip ospf interface");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"line protocol is up", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Installed release : ' + version +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
