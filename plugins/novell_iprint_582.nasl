#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63337);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/08/15 01:01:33 $");

  script_cve_id("CVE-2012-0411");
  script_bugtraq_id(57037);
  script_osvdb_id(88719);

  script_name(english:"Novell iPrint Client < 5.82 Remote Code Execution");
  script_summary(english:"Checks version of Novell iPrint Client");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an application that is affected by a remote
code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Novell iPrint Client installed on the remote host is
earlier than 5.82.  Such versions are affected by an unspecified remote
code execution vulnerability that can be triggered via an 'op-client-
interface-version' action."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-189/");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7008708");
  # script_set_attribute(attribute:"see_also", value:"http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5140890.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91ae2664");
  script_set_attribute(attribute:"solution", value:"Upgrade to Novell iPrint Client 5.82 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:iprint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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

fixed_version = "5.8.2.0";
fixed_version_ui = "5.82";

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
