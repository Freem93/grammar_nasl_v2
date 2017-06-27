#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67229);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/15 16:41:31 $");

  script_cve_id("CVE-2005-2758");
  script_bugtraq_id(15001);
  script_osvdb_id(19854);

  script_name(english:"Symantec AntiVirus Scan Engine Web Service Administrative Interface Buffer Overflow");
  script_summary(english:"Checks version of Symantec AntiVirus Scan Engine");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by a buffer
overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Symantec AntiVirus Scan Engine
installed that is affected by a buffer overflow vulnerability in the
web-based administrative interface.  By sending a specially crafted
request, a remote attacker may be able to execute arbitrary code."
  );
  # http://securityresponse.symantec.com/avcenter/security/Content/2005.10.04.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ceacdf3");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec AntiVirus Scan Engine 4.3.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:antivirus_scan_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("symantec_scan_engine_installed.nasl");
  script_require_keys("SMB/symantec_scan_engine/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

app = 'Symantec AntiVirus Scan Engine';

port = kb_smb_transport();

path = get_kb_item("Symantec/Symantec Scan Engine/Path");

if (isnull(path))
{
  path = get_kb_item_or_exit("Symantec/Symantec AntiVirus Scan Engine/Path");
  version = get_kb_item_or_exit("Symantec/Symantec AntiVirus Scan Engine/Version");
}
else version = get_kb_item_or_exit("Symantec/Symantec Scan Engine/Version");

if (
  version =~ "^4\.[03]\." &&
  ver_compare(ver:version, fix:"4.3.12", strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.3.12\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
