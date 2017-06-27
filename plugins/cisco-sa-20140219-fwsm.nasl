#TRUSTED 9953c4f8e49122b5cc1830d49550ab9fb9e42d42d176f9f625601e245ce293dd735e468c3bc114e941cec12f897ee510aeed2a7f547bf4a7297c9234feac599b29b5db869cb3cde8d5ca29176b894c876dff6bba9dcc2f7ba9d635ecfd251900d2db91df4d27aef7ae6f5768692cea0a0c725069fbdb87ab2e2be25ab3efe2ecf47cd28ccd91a79bbbab3ea101faff0f7703ea2576caa0127b65a895f85fbf762311aa7d859d2d70eba093189a464b5c5930bef9f259878324c001321bcd5ea7fc44ac3b5656d33c9749a33e247933430e3ff6c242738826b3c46238ba8f8490d980b971a3f371fb1e0cb92b5850d7c9c74b32ba44cd00afc452671c7a9f7a0d4476b263b6c367f43f6f68d4a5a98b1dc1f84fa02e80f1719dc01c0658a75181f3dbc2b5d7a0dbb95aa8ec0cab93aa52ade25d8f88fc6c272b1ee2d0145d07ef6ca27a774b5935395dab0c332e994ba193a0210135fb0a7d30cb21afed779530e89233858b894af8b4e37599e22ec59961c3ede4d03e044a571897426cb3c22d855caa65c776e19f3329cd6ff17141e8f232831e45a9a7a9e9b4bc02fadf5cd40e81c953be99dd4729ca65636db4928b9381705cf55408b1ab300873840c90927cbbf242961d367912d8c257a3ae4e621976fd0e2f6ef290e2dc5fd1c46b90af89e6be8938ea807b79cc3ce6e1d6581d3df2dfa51ee927753c740666802f8629
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72668);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/03/01");

  script_cve_id("CVE-2014-0710");
  script_bugtraq_id(65662);
  script_osvdb_id(103468);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj16824");
  script_xref(name:"IAVA", value:"2014-A-0031");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140219-fwsm");

  script_name(english:"Cisco Firewall Services Module Software Denial of Service (cisco-sa-20140219-fwsm)");
  script_summary(english:"Checks the FWSM version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security update.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco Firewall Services Module (FWSM) device is affected by
a denial of service (DoS) vulnerability due to a flaw in the cut-through
proxy function.  A remote, unauthenticated attacker could potentially
exploit this vulnerability to cause a reload of the affected system,
with repeated exploitation leading to a DoS condition."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140219-fwsm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee9fe203");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140219-fwsm."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:firewall_services_module");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_fwsm_version.nasl");
  script_require_keys("Host/Cisco/FWSM/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/FWSM/Version");

flag = 0;
fixed_version = "";
local_checks = 0;

# prepare for local checks if possible
if (get_kb_item("Host/local_checks_enabled"))
{
  local_checks = 1;
}

if ( (version =~ "^3\.1(\.|\()") && (cisco_gen_ver_compare(a:version, b:"3.1(21)") > 0) )
{
  flag++;
  fixed_version = "3.2.x or later";
}

if ( (version =~ "^3\.2(\.|\()") && (cisco_gen_ver_compare(a:version, b:"3.2(28)") < 0) && (cisco_gen_ver_compare(a:version, b:"3.2(21)") > 0))
{
  flag++;
  fixed_version = "3.2(28)";
}

if (version =~ "^4\.0($|\.|\()" && (cisco_gen_ver_compare(a:version, b:"4.0(16)") > 0))
{
  flag++;
  fixed_version = "4.1 or later";
}

if ( (version =~ "^4\.1($|\.|\()") && (cisco_gen_ver_compare(a:version, b:"4.1(15)") < 0) && (cisco_gen_ver_compare(a:version, b:"4.1(6)") > 0))
{
  flag++;
  fixed_version = "4.1(15)";
}

if ( local_checks )
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config_aaa_authentication",
      "show running-config aaa authentication| include match|include"
    );
    if (check_cisco_result(buf)) flag = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
