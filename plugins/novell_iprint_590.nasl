#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66335);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/02/13 14:10:08 $");

  script_cve_id("CVE-2013-1091");
  script_bugtraq_id(59612);
  script_osvdb_id(92938);

  script_name(english:"Novell iPrint Client < 5.90 Stack-Based Buffer Overflow");
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
"The version of Novell iPrint Client installed on the remote host is
earlier than 5.90.  It therefore is reportedly affected by an
unspecified, remote, stack-based buffer overflow vulnerability that
could allow arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-096/");
  # Download
  script_set_attribute(attribute:"see_also", value:"http://download.novell.com/Download?buildid=k6yH0sy992E~");
  # Advisory
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7012344");
  script_set_attribute(attribute:"solution", value:"Upgrade to Novell iPrint Client 5.90 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:iprint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("novell_iprint_532.nasl");
  script_require_keys("SMB/Novell/iPrint/Version", "SMB/Novell/iPrint/Version_UI");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/Novell/iPrint/";

version = get_kb_item_or_exit(kb_base+"Version");
version_ui = get_kb_item_or_exit(kb_base+"Version_UI");
dll = get_kb_item_or_exit(kb_base+"DLL");

fixed_version = "5.9.0.0";
fixed_version_ui = "5.90";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  if (report_verbosity > 0)
  {
    report =
      '\n  File              : ' + dll +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : ' + fixed_version_ui + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, "The Novell iPrint Client DLL '" + dll + "'", version_ui);
