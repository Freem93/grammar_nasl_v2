#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76595);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2014-0247");
  script_bugtraq_id(68151);
  script_osvdb_id(108368);

  script_name(english:"LibreOffice < 4.2.5 Unspecified Macro Code Execution (Mac OS X)");
  script_summary(english:"Checks the version of LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a
vulnerability that allows unspecified VBA macro execution.");
  script_set_attribute(attribute:"description", value:
"A version of LibreOffice is installed on the remote Mac OS X host that
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
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_dependencies("macosx_libreoffice_installed.nasl");
  script_require_keys("MacOSX/LibreOffice/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "MacOSX/LibreOffice";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

if (version =~ "^4\.(1\.[4-6]|2($|\.[0-4]))($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.2.5' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "LibreOffice", version, path);
