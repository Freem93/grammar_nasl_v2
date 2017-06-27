#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84431);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/19 17:45:33 $");

  script_cve_id("CVE-2014-9632");
  script_bugtraq_id(72500);
  script_osvdb_id(113824);
  script_xref(name:"EDB-ID", value:"35993");

  script_name(english:"AVG Internet Security 2013.x < 2013.3495 / 2015.x < 2015.5557 Local Privilege Escalation");
  script_summary(english:"Checks the AVG Internet Security version number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an antivirus application that is affected by
a local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of AVG Internet Security
installed that is 2013.x prior to 2013.3495 or 2015.x prior to
2015.5557. It is, therefore, affected by a local privilege escalation
vulnerability due to a flaw in the TDI driver (avgtdix.sys) that
occurs when handling 0x830020f8 IOCTL calls. A local attacker can
exploit this, via a crafted 0x830020f8 IOCTL call, to write controlled
data to an arbitrary memory location, resulting in arbitrary code
execution with kernel-level privileges.");
  # https://web.archive.org/web/20150321161328/http://www.avg.com/us-en/avg-release-notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbcb1b10");
  script_set_attribute(attribute:"see_also", value:"http://www.greyhathacker.net/?p=818");
  script_set_attribute(attribute:"solution", value:
"Upgrade to AVG Internet Security version 2013.3495 / 2015.5557 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:avg:internet_security");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:avg:protection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("avg_internet_security_installed.nbin");
  script_require_keys("installed_sw/AVG Internet Security");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "AVG Internet Security";

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
path    = install["path"];
version = install["version"];

# The only release notes to mention the vulnerability
# are 2013 and 2015 editions. It is assumed that the 2014
# edition is not affected.
if (version =~ "^2015\.") fix = "2015.5557";
else if (version =~ "^2013\.") fix = "2013.3495";
else fix = NULL;

if (fix && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
