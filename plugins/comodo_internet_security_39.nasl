#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58230);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2009-5125");
  script_bugtraq_id(34737);
  script_osvdb_id(56034);

  script_name(english:"Comodo Internet Security < 3.9 RAR Archive Scan Evasion");
  script_summary(english:"Checks version of Comodo Internet Security");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an antivirus application installed that
is affected by a scan evasion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Comodo Internet Security installed on the remote 
Windows host is earlier than 3.9. As such, it may be possible for 
certain RAR files to evade detection from the scanning engine.");
  script_set_attribute(attribute:"see_also", value:"http://blog.zoller.lu/2009/04/comodo-antivirus-evasionbypass.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Apr/256");
  script_set_attribute(attribute:"see_also", value:"http://www.comodo.com/home/download/release-notes.php?p=anti-malware");
  script_set_attribute(attribute:"solution", value:"Upgrade to Comodo Internet Security 3.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("comodo_internet_security_installed.nasl");
  script_require_keys("SMB/Comodo Internet Security/Path", "SMB/Comodo Internet Security/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

version = get_kb_item_or_exit('SMB/Comodo Internet Security/Version');
path    = get_kb_item_or_exit('SMB/Comodo Internet Security/Path');

if (
  version =~ '^3\\.[5-8]\\.' ||
  (version =~ '^3\\.9\\.' && ver_compare(ver:version, fix:'3.9.95478.509', strict:FALSE) == -1)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.9.95478.509\n';
    security_warning(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_warning(get_kb_item('SMB/transport'));
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Comodo Internet Security', version);
