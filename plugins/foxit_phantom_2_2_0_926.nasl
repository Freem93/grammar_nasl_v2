#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49808);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/18 18:20:36 $");

  script_bugtraq_id(43785);
  script_osvdb_id(68648);
  script_xref(name:"Secunia", value:"41673");

  script_name(english:"Foxit Phantom < 2.2.0.926 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Foxit Phantom");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by 
multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its version, the remote installation of Foxit Phantom on
the Windows host is affected by multiple vulnerabilities :

  - A buffer overflow vulnerability can be triggered when 
    handling a specially crafted PDF document with an overly
    long title.

  - An identity theft flaw exists relating to the way
    digital signatures are handled.");

  script_set_attribute(attribute:"see_also", value:"http://www.foxitsoftware.com/pdf/phantom/version_history.php");
  script_set_attribute(attribute:"see_also", value:"http://pdfsig-collision.florz.de/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Foxit Phantom 2.2.0.926 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Foxit PDF Reader v4.1.1 Title Stack Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/08");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:foxitsoftware:phantom");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

fixed_version = "2.2.0.926";
appname = "FoxitPhantomPDF";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install["path"];
version = install["version"];
name = install["Application Name"];
port = get_kb_item("SMB/transport");
if (!port)
  port = 445;

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  security_report_v4(port:port, extra:
    '\n  Application Name  : ' + name +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version,
    severity:SECURITY_HOLE);
}
else
{
  audit(AUDIT_INST_VER_NOT_VULN, name, version);
}
exit(0);
