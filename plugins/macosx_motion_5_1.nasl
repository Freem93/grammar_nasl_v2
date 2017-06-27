#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71571);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/12/20 20:44:40 $");

  script_cve_id("CVE-2013-6114");
  script_bugtraq_id(62874);
  script_osvdb_id(98169);
  script_xref(name:"EDB-ID", value:"28811");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-12-19-1");

  script_name(english:"Apple Motion < 5.1 OZDocument::parseElement() Function MOTN File Subview Attribute Handling Integer Overflow");
  script_summary(english:"Check the version of Motion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application on the remote host is affected by an integer overflow
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple Motion installed on the remote Mac OS X host is
earlier than 5.1.  As such, it reportedly has an integer overflow in
its handling of .motn files that could lead to an out-of-bounds memory
access and, in turn, arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Oct/27");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6041");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/530434/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Motion 5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:motion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("macosx_motion_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Motion/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/MacOSX/Version")) audit(AUDIT_OS_NOT, "Mac OS X");

get_kb_item_or_exit("MacOSX/Motion/Installed");
path = get_kb_item_or_exit("MacOSX/Motion/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Motion/Version", exit_code:1);

fixed_version = "5.1";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Apple Motion", version, path);
