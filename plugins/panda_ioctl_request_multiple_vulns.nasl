#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47697);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/06/19 21:37:39 $");

  script_bugtraq_id(41428);
  script_osvdb_id(66041, 66042);
  script_xref(name:"Secunia", value:"40506");
  script_xref(name:"Secunia", value:"40462");

  script_name(english:"Panda Products RKPavProc.sys IOCTL Handling Vulnerabilities");
  script_summary(english:"Checks version of rkpavproc.sys");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an antivirus application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed Panda security product is reportedly affected by
multiple vulnerabilities in the 'RKPavProc.sys' kernel driver that can
be triggered by specially crafted IOCTLs, leading to a NULL pointer
dereference or a stack-based buffer overflow. An attacker could
leverage these flaws to cause a denial of service or execute arbitrary
code on the remote host with elevated privileges.");

  script_set_attribute(attribute:"see_also", value:"http://www.ntinternals.org/ntiadv0905/ntiadv0905.html");
  script_set_attribute(attribute:"see_also", value:"http://www.pandasecurity.com/homeusers/support/card?id=80184&idIdioma=2");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix as discussed in the vendor advisory
above.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pandasecurity:panda_antivirus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "panda_antivirus_installed.nasl");
  script_require_keys("Antivirus/Panda/installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

# Make sure Panda Antivirus is installed
get_kb_item_or_exit("Antivirus/Panda/installed");

# Connect to the appropriate share
name    = kb_smb_name();
port    = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

vuln = FALSE;

list = get_kb_list("Antivirus/Panda/*");
pat = "^([0-9\.]+) in (.+)";
foreach item (keys(list))
{
  matches = eregmatch(string:list[item], pattern:pat);
  if (!isnull(matches))
  {
    path = matches[2];

    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
    if (!is_accessible_share(share:share)) exit(1, "Can't access '"+share+"' share.");

    if (hotfix_check_fversion(file:"rkpavproc.sys", path:path, version:"1.0.10.0") == HCF_OLDER)
    {
      vuln = TRUE;
      if (!thorough_tests) break;
    }
  }
}
if (vuln)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

