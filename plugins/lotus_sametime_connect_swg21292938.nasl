#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70072);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:02:52 $");

  script_cve_id("CVE-2008-0354");
  script_bugtraq_id(27316);
  script_osvdb_id(40536);
  script_xref(name:"IAVA", value:"2008-A-0001");

  script_name(english:"IBM Lotus Sametime Connect Client Mouseover XSS");
  script_summary(english:"Checks version of IBM Lotus Sametime Connect Client");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a chat client installed that is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Lotus Sametime Connect installed on the remote
Windows host is 7.5 or 7.5.1.  Such versions are potentially affected by
a cross-site scripting vulnerability.  By tricking a user into moving
the mouse cursor over specially crafted content, an attacker could
execute arbitrary script code on the remote host subject to the
privileges of the user running the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21292938");
  script_set_attribute(attribute:"solution", value:"Upgrade to Lotus Sametime Connect Client 7.5.1 CF1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_sametime");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("lotus_sametime_connect_installed.nasl");
  script_require_keys("SMB/IBM Lotus Sametime Client/Path", "SMB/IBM Lotus Sametime Client/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('SMB/IBM Lotus Sametime Client/Version');
path    = get_kb_item_or_exit('SMB/IBM Lotus Sametime Client/Path');

if (version =~ '^7\\.5($|[^\\.0-9]|\\.(0([^0-9]|$)|1($|CF1)))')
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  set_kb_item(name:"www/0/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, 'IBM Lotus Sametime Connect', version, path);
