#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(61621);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/09/18 15:16:40 $");

  script_cve_id("CVE-2012-0681");
  script_bugtraq_id(55100);
  script_osvdb_id(84848);

  script_name(english:"Apple Remote Desktop < 3.5.3 / 3.6.1 Information Disclosure (Mac OS X)");
  script_summary(english:"Reads version from Info.plist");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Mac OS X host has a remote management tool that is affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the Admin component in the Apple Remote
Desktop install on the remote host reportedly fails to encrypt data 
and does not issue a warning when connecting to a third-party VNC 
server with 'Encrypt all network data' set.  This could lead to 
information disclosure."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5433");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Aug/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Remote Desktop 3.5.3 / 3.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_remote_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("macosx_remote_desktop_admin_installed.nasl");
  script_require_keys("MacOSX/Remote_Desktop_Admin/Installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "MacOSX/Remote_Desktop_Admin";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

# nb: "This issue does not affect Apple Remote Desktop 3.5.1 and earlier."
if (
  ereg(pattern:"^3\.5\.2($|[^0-9])", string:version) ||
  ereg(pattern:"^3\.6(\.0)?($|[^0-9.])", string:version)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 3.5.3 / 3.6.1' +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Apple Remote Desktop", version, path);
