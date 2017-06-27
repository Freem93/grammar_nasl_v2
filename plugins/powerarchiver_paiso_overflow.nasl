#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23976);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/02 14:37:08 $");

  script_cve_id("CVE-2007-0097");
  script_bugtraq_id(21867);
  script_osvdb_id(32576);

  script_name(english:"PowerArchiver paiso.dll ISO Image Handling Buffer Overflow");
  script_summary(english:"Checks PowerArchiver file version");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a utility that is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains PowerArchiver, a file compression utility for
Windows.

The version of PowerArchiver installed on the remote host has a buffer
overflow in the 'paiso.dll' library file that can be triggered when
processing the full pathname of a file within an ISO image. If an
attacker can trick a user on the affected host into opening a
specially crafted ISO image file, he can leverage this issue to
execute arbitrary code on the host subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://vuln.sg/powarc964-en.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jan/101" );
  script_set_attribute(attribute:"solution", value:"Upgrade to PowerArchiver 9.64.03 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:powerarchiver:powerarchiver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("powerarchiver_detect.nbin");
  script_require_keys("SMB/PowerArchiver/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "PowerArchiver";
kb_base = "SMB/PowerArchiver/";

version = get_kb_item_or_exit(kb_base + "Version");
path = get_kb_item_or_exit(kb_base + "Path");

fix = "9.6.4.3";
if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0) audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

port = get_kb_item("SMB/transport");
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
