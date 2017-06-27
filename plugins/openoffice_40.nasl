#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69185);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/31 01:51:50 $");

  script_cve_id("CVE-2013-2189", "CVE-2013-4156");
  script_bugtraq_id(61465, 61468);
  script_osvdb_id(95704, 95706);

  script_name(english:"Apache OpenOffice < 4.0 Multiple Memory Corruption Vulnerabilities");
  script_summary(english:"Checks the version of Apache OpenOffice.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a program affected by multiple memory
corruption vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apache OpenOffice installed on the remote host is prior
to 4.0. It is, therefore, affected by memory corruption
vulnerabilities related to the handling of PLCF (Plex of Character
Positions in File) data and unknown XML elements in OOXML files. This
can lead to application crashes and, potentially, other unspecified
impacts."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2013-2189.html");
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2013-4156.html");
  script_set_attribute(attribute:"see_also", value:"https://blogs.apache.org/OOo/entry/a_short_celebration_and_then");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache OpenOffice version 4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:openoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("openoffice_installed.nasl");
  script_require_keys("SMB/OpenOffice/Build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

build = get_kb_item_or_exit("SMB/OpenOffice/Build");
path  = get_kb_item("SMB/OpenOffice/Path");
version_ui = get_kb_item("SMB/OpenOffice/Version_UI");

matches = eregmatch(string:build, pattern:"([0-9]+[a-z][0-9]+)\(Build:([0-9]+)\)");
if (isnull(matches)) audit(AUDIT_VER_FAIL, "OpenOffice");

buildid = int(matches[2]);
if (buildid <= 9593)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 4.0 (400m3 / build 9702)' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "OpenOffice", version_ui, path);
