#TRUSTED a595f47863192fe09633deef4c2e6a18a321155870953222d37efd5e7ffe67beba7ad3c57ca9cf61995cbf888a5be2ca349b602f5ae9525044681716a5e005daa6a13f4a04be4517dd02de1b87691a0ef1e6e77210541f8599aaa25c1fe78047212ee48c1117377259297e9acf33b902521be326d8fd37310fcd6fef05131179d92bb00719a73cb76b6ac567bbc08ab6eb34cacebf37b19609777f65bfbe71b5420e89ea54cbad8620b82a9f0731430e575426972161ac45f97b99223d3ad407bf9066ac5c43a7d5e3475f185f0a75e657f43b3afb4239b4db2e549fbad11e686a53f5dd35b46c7408109a4ce3917887f03b60b212c31be6c22da0ca697881f7a557354b74f5bfc7c7c651ff129acf37cc01c5716fd3a70b1b160f840757108ae60b518089b1e90d101677d833490ce29ffce6c14eff986a438c01a4aff4a505d7c0818a38b38594deb01330ff161de5384c7c330c13674fe50daa02725e5d58be4eb6078c1fd89c336aba7558176a2dad3d46eb784a9f41d381165baf2d3da4ce408930813146aa5fdf5e9ccf694346b2917a54706dc62c2fd2b97d355f570547c32884600219ee4cc8151562eab096693048dcb656d112aabc3ded783af907d6d143c099d36430ba8c789a8cd3a1f5eff4c870ff6ff4d66328c2dfc475f09897df711a038427a29779023e4c951dc0f794c4d29a0dfc0d253de3531aaacdd6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70493);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/03/01");

  script_cve_id("CVE-2013-5506", "CVE-2013-5508");
  script_bugtraq_id(62912, 62918);
  script_osvdb_id(98255, 98256);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue46080");
  script_xref(name:"CISCO-BUG-ID", value:"CSCui34914");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20131009-fwsm");

  script_name(english:"Cisco Firewall Services Module Software Multiple Vulnerabilities (cisco-sa-20131009-fwsm)");
  script_summary(english:"Checks the FWSM version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco Firewall Services Module (FWSM) device is affected
by one or both of the following vulnerabilities.

  - A flaw exists in FWSM that could allow an authenticated,
    unprivileged, local attacker to execute certain commands
    in any other context of the affected system.
    (CVE-2013-5506)

  - A flaw exists in FWSM in the SQL*Net Inspection Engine
    that could allow a remote denial of service that could
    be triggered when handling a malformed TNS packet.
    (CVE-2013-5508)"
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20131009-fwsm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49e2b9a9");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20131009-fwsm."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:firewall_services_module");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/18");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_fwsm_version.nasl");
  script_require_keys("Host/Cisco/FWSM/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/FWSM/Version");

flag = 0;
override = 0;
fixed_version = "";
local_checks = 0;

# prepare for local checks if possible
if (get_kb_item("Host/local_checks_enabled"))
{
  local_checks = 1;
}

# CSCue46080
temp_flag = 0;
if ( (version =~ "^3\.1(\.|\()") && (cisco_gen_ver_compare(a:version, b:"3.1(8)") > 0) )
{
  temp_flag++;
  fixed_version = "3.2.x or later";
}

if ( (version =~ "^3\.2(\.|\()") && (cisco_gen_ver_compare(a:version, b:"3.2(25)") < 0) && (cisco_gen_ver_compare(a:version, b:"3.2(4)") > 0))
{
  temp_flag++;
  fixed_version = "3.2(25)";
}

if (version =~ "^4\.0($|\.|\()")
{
  temp_flag++;
  fixed_version = "4.1.(14) or later";
}

if ( (version =~ "^4\.1($|\.|\()") && (cisco_gen_ver_compare(a:version, b:"4.1(13)") < 0) )
{
  temp_flag++;
  fixed_version = "4.1(13)";
}

if ( local_checks )
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_mode", "show mode");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"multiple", string:buf)) { temp_flag = 1; }
    }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco Bug Id        : CSCue46080' +
    '\n    Installed version : ' + version +
    '\n    Fixed version     : ' + fixed_version + '\n';

  flag = 1;
}

# CSCui34914
temp_flag = 0;
if (version =~ "^3\.1($|\.|\()")
{
  temp_flag++;
  fixed_version = "3.2.x or later";
}

if ( (version =~ "^3\.2($|\.|\()") && (cisco_gen_ver_compare(a:version, b:"3.2(27)") < 0) )
{
  temp_flag++;
  fixed_version = "3.2(27)";
}

if (version =~ "^4\.0($|\.|\()")
{
  temp_flag++;
  fixed_version = "4.1.(14) or later";
}

if ( (version =~ "^4\.1($|\.|\()") && (cisco_gen_ver_compare(a:version, b:"4.1(14)") < 0) )
{
  temp_flag++;
  fixed_version = "4.1(14)";
}

if ( local_checks )
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_service-policy", "show service-policy");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"[Ii]nspect\s*:\s*sqlnet", string:buf)) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco Bug Id        : CSCui34914' +
    '\n    Installed version : ' + version +
    '\n    Fixed version     : ' + fixed_version + '\n';

  flag = 1;
}

if (flag)
{
  if (report_verbosity > 0)
  {
    security_hole(port:0, extra:cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
