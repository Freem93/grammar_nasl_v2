#TRUSTED 4ebfe7499318c068d967e418626b81082bcfe9df6563916ecbabe0b73b9115475bfbeef65a20b5b9d09e8fed52d9c03345b169ae1ee77902e55ead0c8fb691834a0fad0aaad66ddc050ae413ef8ec3e31f13978302160886d5a1ab667b1728da929ab07c8bfa5bfa8b2412cfa5df18c283218db392a8e28d1028aa5ed63866f655cfedfdf938d5b7d8bd4f4430084ae89427feb767fbc098793d032c3e5a639267f21af203c60d7753fe78d34f40ba087448f200e08a0aeea9fcea1411ba70e9c9b926e311cbbfbb940f607d1055a24445b35db710aef47e97ded13d81f08455029f735f3a44822d984de2eec0417593df9977b0821c0a950c12e3ed64b19a70cd189892c7c9dd2252cab2c0c08e2b1279badae4f055246571250fbf7cdff828ef8be6f7fe18332888659d4870ef994dfe2e28d41a9d375202ce77695e10e1525df4e180c2e9ff9b0d0bb61d2a7c1c97fd87e706a78f1d11260b34f817006b422b45b8a0ef4564eadb5ddc6cad3b7f7ebec09850590ee1d4b1e146a233cc3f6dd11d88ef5a7cc9fc0a874813b594bfe7b7b8e95695cbfc8c9b9c876c59586a23a3f9776c6ae7e377005fc566e74982fd8db41810acc3132f05e0d4627b01f566fa6380c1aff3d430b6ca51f45f97ad00129cb691062490df508ce0c9f8c07139089247c1eaaf5ebc2c5ae6a7d85c11127481032bb861185bca42d314417d4f3a
#
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68961);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2008-3819");
  script_bugtraq_id(33152);
  script_osvdb_id(51262, 51391);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsj70093");
  script_xref(name:"IAVT", value:"2009-T-0004");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20090107-gss");

  script_name(english:"Cisco Global Site Selector Appliances DNS Vulnerability (cisco-sa-20090107-gss)");
  script_summary(english:"Checks the GSS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Application Control Engine Global Site Selector (GSS)
contains a denial of service (DoS) issue when processing specific Domain
Name System (DNS) requests.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20090107-gss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76cadf6e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090107-gss.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:gss_4480_global_site_selector");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:gss_4490_global_site_selector");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:gss_4491_global_site_selector");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:gss_4492r_global_site_selector");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/18");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_gss_version.nasl");
  script_require_keys("Host/Cisco/GSS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
report_extras = "";

model = get_kb_item_or_exit("Host/Cisco/GSS/model");
version = get_kb_item_or_exit("Host/Cisco/GSS/Version");

if ( (model != "4480") && (model != "4490") && (model != "4491") && (model != "4492r") )
  audit(AUDIT_HOST_NOT, "GSS model 4480/4490/4491/4492r");

if ( version =~ "^1\." ) flag++;
if ( version =~ "^2\." ) flag++;

if (flag)
{
  if (get_kb_item("Host/local_checks_enabled"))
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running", "show running");
    if (check_cisco_result(buf))
    {
      if ( (preg(pattern:"cnr enable", multiline:TRUE, string:buf)) && (!preg(pattern:"no cnr enable", multiline:TRUE, string:buf)) )
      {
        flag = 0;
      }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
