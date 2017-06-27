
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61731);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/09/02 15:06:43 $");

  script_cve_id("CVE-2012-2665");
  script_bugtraq_id(54769);
  script_osvdb_id(84440, 84441, 84442);

  script_name(english:"Apache OpenOffice < 3.4.1 Multiple Heap-Based Buffer Overflows");
  script_summary(english:"Checks the version of Apache OpenOffice.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a program affected by multiple 
heap-based buffer overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apache OpenOffice installed on the remote host is prior
to 3.4.1. It is, therefore, affected by multiple heap-based buffer
overflow vulnerabilities related to XML manifest handling :

  - An error exists related to handling the XML tag
    hierarchy.

  - A boundary error exists when handling the duplication
    of certain unspecified XML tags.

  - An error exists in the base64 decoder related to XML
    export actions."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.openoffice.org/security/cves/CVE-2012-2665.html");
  script_set_attribute(attribute:"see_also", value:"http://blogs.apache.org/OOo/entry/announcing_apache_openoffice_3_41");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache OpenOffice version 3.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:openoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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
if (buildid < 9593) 
{
  port = get_kb_item("SMB/transport");
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 3.4.1 (341m1 / build 9593)' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "OpenOffice", version_ui, path);
