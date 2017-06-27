#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58649);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/10 20:42:51 $");

  script_bugtraq_id(52826);
  script_osvdb_id(80816);
  script_xref(name:"EDB-ID", value:"18681");

  script_name(english:"Bitsmith Software Personal Knowbase knowbase.exe FileOpen Dialogue Local Overflow");
  script_summary(english:"Checks version of Bitsmith Personal Knowbase");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application installed on the remote Windows host is affected by a
buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Bitsmith Personal Knowledge base installed on the
remote Windows host is prior to 3.2.4. It is, therefore, affected by a
local buffer overflow vulnerability that can be triggered by
specifying an oversized string for a specific registry value. This
vulnerability may allow for arbitrary code to be executed subject to
the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.vulnerability-lab.com/get_content.php?id=474");
  script_set_attribute(attribute:"see_also", value:"http://www.bitsmithsoft.com/pkhist.htm#vers324");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Bitsmith Personal Knowbase 3.2.4 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:bitsmith:personal_knowbase");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("bitsmith_knowbase_installed.nasl");
  script_require_keys("SMB/Bitsmith_Knowbase/Installed");

  exit(0);
}
 
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/Bitsmith_Knowbase/";
port = get_kb_item("SMB/transport");

get_kb_item_or_exit(kb_base + "Installed");
num_installs = get_kb_item_or_exit(kb_base + "NumInstalls");

report = "";

for (install_num = 0; install_num < num_installs; install_num++)
{
  version = get_kb_item(kb_base + install_num + "/Version");

  if (ver_compare(ver:version, fix:'3.24.2.205', strict:FALSE) == -1)
  {
    path = get_kb_item(kb_base + install_num + "/Path");
    version_ui = get_kb_item(kb_base + install_num + "/Version_UI");
    report += '\n  Path              : '+path+
              '\n  Installed version : '+version_ui+ ' (' + version + ')' +
              '\n  Fixed version     : 3.2.4 (3.24.2.205)\n';
  }
}

if (report != "")
{
  if (report_verbosity > 0) security_note(port:port, extra:report); 
  else security_note(port);
  exit(0);
}
else exit(0, "No affected installs of Bitsmith Personal Knowbase were found."); 
