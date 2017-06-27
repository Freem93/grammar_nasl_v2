#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72337);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/05 18:14:38 $");

  script_cve_id("CVE-2014-1213");
  script_bugtraq_id(65286);
  script_osvdb_id(102762);

  script_name(english:"Sophos Anti-Virus Engine < 3.50.1 System Objects DoS");
  script_summary(english:"Checks the virus engine number");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application on the remote Windows host is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Sophos Anti-Virus install on the remote host uses an engine version
earlier than 3.50.1.  As such, it reportedly has a misconfigured Access
Control List (ACL) on certain system objects that could allow a local
attacker to cause the host to become sluggish and eventually crash, or
display false 'ready for update' message popups.");
  # http://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-1213/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80e5b8f4");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Feb/1");
  # http://www.sophos.com/en-us/support/knowledgebase/2300/7200/1031/120401.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47f14129");
  script_set_attribute(attribute:"solution", value:"Upgrade to Sophos Anti-Virus engine version 3.50.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:sophos_anti-virus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("sophos_installed.nasl");
  script_require_keys("Antivirus/Sophos/installed", "Antivirus/Sophos/eng_ver");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Antivirus/Sophos/eng_ver");
path = get_kb_item_or_exit("Antivirus/Sophos/path");

fix = "3.50.1";

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
     report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Sophos Anti-Virus', version, path);
