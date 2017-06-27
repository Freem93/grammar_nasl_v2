#TRUSTED a1dceaea277992d71e3900f728d409f6f00ea067c90972584aa452790c8fadb10dd83a30e8c07b9278283caa7eb8782432f557a3ed468a1e2c4adcbeccb536d5b6105e8e1126a6c0c4596349452f44addb0b5f3fd82b03e1f442f9bed720cdd777cf748bb34c2f749756955fdd141b2f52bd713dcd59fbb8fd48e28e58b32c6f4cc4827a201ceb21fabe71890486bf64c70b8426884ef424f1ab216cbe3e28e131af8b171b1c1b37412ecd9ec10358907d767e4688af18f77893cb32ac4dfb9d73dac5af98b97b7b523fc16874b54f79bb8dbfae8c560553360f2431fd9f7adf26700f88427a2ad864ebf1601227a0fa010a10a0c0d2f876c247a82639339f1848a30066f4dfc7f4ab3a16648eca315d95e213cb8f5e2c51587fa4dc225141811762404b4c69e7b7feb18140e224ec25c516c20f26c21275b74b0293302a57e90d28f4f659e8cb8cbd38fa305ffa86e50eea2d11e6f7f67348390f5119166a96f28713bdd87061e438a27e104c248f2948f0e43e99fd0d74480b74db854619dc6a5ae3f6515e133238696aac82578a2406fbc705a87517a2838db358fd54bfd8923b286f6ceefb0b250aedf807b27075e2927c9debae0bff9c087828c5ecf49be1cca48fe6287c8312e4f8c42a0ddbcb7038c1738d8278a55d4864b721ab48dfdc440609b33b0ccb3421bd8b55602ec472dd0ec9469f89e9344a7f64260d419a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69335);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/04/08");

  script_cve_id("CVE-2008-2060");
  script_bugtraq_id(29791);
  script_osvdb_id(46466);
  script_xref(name:"CISCO-BUG-ID", value:"CSCso64762");
  script_xref(name:"IAVT", value:"2008-T-0030");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20080618-ips");

  script_name(english:"Cisco Intrusion Prevention System Jumbo Frame Denial of Service (cisco-sa-20080618-ips)");
  script_summary(english:"Checks IPS version");

  script_set_attribute(attribute:"synopsis", value:"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of the Cisco
Intrusion Prevention System Software running on the remote host may be
vulnerable to a denial of service (DoS) attack caused by a kernel panic.
This is due to the handling of jumbo Ethernet frames when gigabit
network interfaces are installed and are deployed in inline mode."
  );
  # http://www.cisco.com/en/US/products/csa/cisco-sa-20080618-ips.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8fcb273");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20080618-ips."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:intrusion_prevention_system");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_ips_version.nasl");
  script_require_keys("Host/Cisco/IPS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");


##
# Compares two strings representing versions. (assumes the strings are "." delimited.
#
# @param fix     The second version string.
# @param ver     The first version string.
#
# @return -1 if ver < fix, 0 if ver == fix, or 1 if ver > fix.
##
function ips_ver_compare(fix, ver)
{
  local_var ffield, vfield, flen, vlen, len, i;
  # replace ( and ) with dots to make comparisons more accurate
  ver = ereg_replace(pattern:'[()]', replace:".", string:ver);
  fix = ereg_replace(pattern:'[()]', replace:".", string:fix);
  # Break apart the version strings into numeric fields.
  ver = split(ver, sep:'.', keep:FALSE);
  fix = split(fix, sep:'.', keep:FALSE);
  # Both versions must have the same number of fields when
  # when doing a strict comparison.
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
    if ( (int(vfield) == vfield) && (int(ffield) == ffield) )
    {
      vfield = int(ver[i]);
      ffield = int(fix[i]);
    }
    if (vfield < ffield) return -1;
    if (vfield > ffield) return 1;
  }
  return 0;
}

ver = get_kb_item_or_exit('Host/Cisco/IPS/Version');
model = get_kb_item_or_exit('Host/Cisco/IPS/Model');
display_fix = "";

if (model =~ "4235" ||
    model =~ "4240" ||
    model =~ "4250" ||
    model =~ "4250SX" ||
    model =~ "4250TX" ||
    model =~ "4250XL" ||
    model =~ "4255" ||
    model =~ "4260" ||
    model =~ "4270")
{
  if ( (ver =~ "^5\.") && (ips_ver_compare(ver:ver, fix:"5.1(8)E2") < 0) )
    display_fix = "5.1(8)E2";
  if ( (ver =~ "^6\.") && (ips_ver_compare(ver:ver, fix:"6.0(5)E2") < 0) )
    display_fix = "6.0(5)E2";
}

if (display_fix == "")
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IPS', ver);

flag = 1;
override = 0;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_interfaces", "show interfaces");
  if (check_cisco_result(buf))
  {
    if (preg(pattern:"Inline Mode = Paired with", multiline:TRUE, string:buf)) { flag = 1; }
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + display_fix + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");

