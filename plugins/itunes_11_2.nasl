#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74040);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/16 14:02:52 $");

  script_cve_id("CVE-2014-1296", "CVE-2014-8842");
  script_bugtraq_id(67024);
  script_osvdb_id(106145, 137872);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-04-22-2");

  script_name(english:"Apple iTunes < 11.2 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks version of iTunes on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote host is prior to
version 11.2. It is, therefore, affected by multiple vulnerabilities :

  - A flaw exists in the CFNetwork HTTPProtocol due to a
    failure to properly ensure that a Set-Cookie HTTP header
    is complete before interpreting the header's value. A
    man-in-the-middle attacker can exploit this to bypass
    security settings by closing the connection before the
    security settings are sent, resulting in the disclosure
    of sensitive information. (CVE-2014-1296)

  - A memory corruption issue exists due to improper
    validation of user-supplied input when handling MP4
    files. An attacker can exploit this, by convincing a
    user to open a specially crafted MP4 file, to corrupt
    memory, resulting in the execution of arbitrary code.
    (CVE-2014-8842)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6245");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/532116/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 11.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/iTunes/Version");
path = get_kb_item_or_exit("SMB/iTunes/Path");

fixed_version = "11.2.0.115";
if (ver_compare(ver:version, fix:fixed_version) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version+
      '\n  Fixed version     : '+fixed_version+'\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "iTunes", version, path);
