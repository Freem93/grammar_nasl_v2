#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65789);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2013-0130");
  script_bugtraq_id(58634);
  script_osvdb_id(91590);
  script_xref(name:"CERT", value:"370868");

  script_name(english:"Core FTP < 2.2 build 1769 Multiple Buffer Overflows");
  script_summary(english:"Checks version of Core FTP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An FTP client on the remote host is affected by multiple buffer
overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Core FTP installed on the remote host is prior to 2.2
build 1769 (2.2.1768.0).  It is, therefore, affected by multiple buffer
overflow vulnerabilities because user-supplied input is not properly
validated when handling directory names.  A remote attacker could
potentially exploit this issue with specially crafted directory names,
resulting in a denial of service or code execution subject to the user's
privileges. 

Note that the fix for this issue is version 2.2 Build 1769 while the
actual file version is 2.2.1768.");
  script_set_attribute(attribute:"see_also", value:"http://coreftp.com/forums/viewtopic.php?t=137481");
  script_set_attribute(attribute:"solution", value:"Upgrade to Core FTP 2.2 build 1769 (2.2.1768.0) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:coreftp:coreftp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("coreftp_stack_overflow.nasl");
  script_require_keys("SMB/CoreFTP/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = 'Core FTP';
kb_base = "SMB/CoreFTP/";

path = get_kb_item_or_exit(kb_base + "Path");
version = get_kb_item_or_exit(kb_base + "Version");

# nb: While the build is 2.2.1769, the actual file version is 2.2.1768.
fix = "2.2.1768.0";

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report = '\n  File              : ' + path + "coreftp.exe" +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
