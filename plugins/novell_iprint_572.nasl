#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56682);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id("CVE-2011-3173");
  script_bugtraq_id(50367);
  script_osvdb_id(76631);

  script_name(english:"Novell iPrint Client < 5.72 nipplib.dll GetDriverSettings Function Buffer Overflow");
  script_summary(english:"Checks version of Novell iPrint Client");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an application that is affected by a buffer
overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The nipplib.dll component included with the installed version of
Novell iPrint Client blindly copies user input provided as a parameter
to the 'GetDriverSettings' method into a fixed-length buffer on the
stack.  By tricking the user into opening a specially crafted file, an
attacker can leverage this issue to overflow a buffer and execute
arbitrary code in the context of the affected application."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-309/");
  script_set_attribute(attribute:"see_also", value:"http://download.novell.com/Download?buildid=bSpj4nhVEZ0~");
  script_set_attribute(attribute:"solution", value:"Upgrade to Novell iPrint Client 5.72 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-166");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:iprint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("novell_iprint_532.nasl");
  script_require_keys("SMB/Novell/iPrint/Version", "SMB/Novell/iPrint/Version_UI");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/Novell/iPrint/";

version = get_kb_item_or_exit(kb_base+"Version");
version_ui = get_kb_item_or_exit(kb_base+"Version_UI");
dll = get_kb_item_or_exit(kb_base+"DLL");

fixed_version = "5.7.2.0";
fixed_version_ui = "5.72";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item(kb_base+"Path");
    if (isnull(path)) path = 'n/a';

    report =
      '\n  File              : '+dll+
      '\n  Installed version : '+version_ui+
      '\n  Fixed version     : '+fixed_version_ui+'\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The Novell iPrint Client "+version_ui+" install on the host is not affected.");
