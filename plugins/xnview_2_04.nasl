#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69137);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/01 19:59:57 $");

  script_cve_id("CVE-2013-2577", "CVE-2013-3492", "CVE-2013-3493");
  script_bugtraq_id(61397, 61503, 61505);
  script_osvdb_id(95580);
  script_xref(name:"Secunia", value:"54174");
  script_xref(name:"EDB-ID", value:"27049");

  script_name(english:"XnView 2.x < 2.04 Multiple Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks XnView.exe's Product Version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains an application that is affected by
multiple buffer overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of XnView installed on the remote Windows host is 2.x,
earlier than 2.04.  It is, therefore, reportedly affected by the
following overflow vulnerabilities:

  - An unspecified error exists that could allow a buffer
    overflow during 'PCT' file handling. (CVE-2013-2577)

  - Unspecified errors exist that could allow heap-based
    buffer overflows during 'FPX' and 'PSP' file handling.
    (CVE-2013-3492, CVE-2013-3493)"
  );
  # Release notes
  script_set_attribute(attribute:"see_also", value:"http://newsgroup.xnview.com/viewtopic.php?f=35&t=28400");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Jul/152");
  script_set_attribute(attribute:"solution", value:"Upgrade to XnView version 2.04 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:xnview:xnview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("xnview_rgbe_overflow.nasl");
  script_require_keys("SMB/XnView/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/XnView";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path");
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

# Check the version number.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# 2.00 < 2.03
if (ver[0] == 2 && ver[1] < 4)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.04\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "XnView", version, path);
