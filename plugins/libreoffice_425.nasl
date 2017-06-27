#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76594);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2014-0247");
  script_bugtraq_id(68151);
  script_osvdb_id(108368);

  script_name(english:"LibreOffice < 4.2.5 Unspecified Macro Code Execution");
  script_summary(english:"Checks the version of LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a
vulnerability that allows unspecified VBA macro execution.");
  script_set_attribute(attribute:"description", value:
"A version of LibreOffice is installed on the remote Windows host that
is between versions 4.1.4 and 4.2.4. It is, therefore, affected by a
vulnerability that allows the execution of unspecified VBA macros
automatically.

Note that Nessus has not attempted to exploit this issue, but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:"Upgrade to LibreOffice version 4.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://www.libreoffice.org/about-us/security/advisories/CVE-2014-0247");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("SMB/LibreOffice/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/LibreOffice";
version = get_kb_item_or_exit(kb_base+"/Version");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version_ui = get_kb_item_or_exit(kb_base+"/Version_UI", exit_code:1);

# Versions 4.1.4-4.1.6 and 4.2-4.2.4 are affected
if (version =~ "^4\.(1\.[4-6]|2($|\.[0-4]))($|[^0-9])")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 4.2.5' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "LibreOffice", version_ui, path);
