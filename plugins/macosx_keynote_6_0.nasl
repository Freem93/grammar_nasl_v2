#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70611);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/10/25 18:41:27 $");

  script_cve_id("CVE-2013-5148");
  script_bugtraq_id(63283);
  script_osvdb_id(98874);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-22-4");

  script_name(english:"Apple Keynote < 6.0 Presentation Mode Lock Engagement Screen Lock Bypass");
  script_summary(english:"Check the version of Keynote");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application on the remote host is affected by a security bypass
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple Keynote installed on the remote Mac OS X host is
earlier than 6.0.  As such, it reportedly suffers from a vulnerability
in which the screen lock may not be engaged when the computer is put to
sleep while in Keynote presentation mode under certain conditions."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6002");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Oct/msg00005.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Keynote 6.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:keynote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("macosx_keynote_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Keynote/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/MacOSX/Version")) audit(AUDIT_OS_NOT, "Mac OS X");

get_kb_item_or_exit("MacOSX/Keynote/Installed");
path = get_kb_item_or_exit("MacOSX/Keynote/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Keynote"+path+"/Version", exit_code:1);

fixed_version = "6.0";

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
else audit(AUDIT_INST_PATH_NOT_VULN, "Apple Keynote", version, path);
