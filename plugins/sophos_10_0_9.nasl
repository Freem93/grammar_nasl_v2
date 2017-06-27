#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(62948);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/30 21:51:49 $");

  script_bugtraq_id(56401);
  script_osvdb_id(87056, 87057, 87058, 87059, 87060, 87061, 87062, 87063);
  script_xref(name:"CERT", value:"662243");

  script_name(english:"Sophos Anti-Virus < 10.0.9 / 10.2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the product's version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an antivirus application that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Sophos Anti-Virus installation on
the remote Windows host is affected by multiple vulnerabilities :

  - An integer overflow exists when parsing Visual Basic 6
    controls.

  - An ASLR bypass exists in 'sophos_detoured_x64.dll'.

  - A universal cross-site scripting vulnerability exists
    in the template for the LSP block page.

  - A memory corruption issue exists in the Microsoft CAB
    parsers.

  - A memory corruption issue exists in the RAR virtual
    machine standard filters.

  - A privilege escalation vulnerability exists in the
    network update service.

  - A stack-based buffer overflow issue exists in the PDF
    file decrypter.");
  script_set_attribute(attribute:"see_also", value:"https://lock.cmpxchg8b.com/sophailv2.pdf");
  script_set_attribute(attribute:"see_also", value:"http://nakedsecurity.sophos.com/2012/11/05/tavis-ormandy-sophos/");
  script_set_attribute(attribute:"see_also", value:"http://www.sophos.com/en-us/support/knowledgebase/118424.aspx");
  script_set_attribute(attribute:"solution", value:"Upgrade to Sophos Anti-Virus version 10.0.9 / 10.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:sophos_anti-virus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("sophos_installed.nasl");
  script_require_keys("Antivirus/Sophos/installed", "Antivirus/Sophos/prod_ver");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Get the product version.
version = get_kb_item_or_exit("Antivirus/Sophos/prod_ver");
path = get_kb_item_or_exit("Antivirus/Sophos/path");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = split("10.0.9", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<3; i++)
{
  if ((ver[i] < fix[i]))
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 10.0.9 / 10.2.1\n';
      security_hole(port:get_kb_item("SMB/transport"), extra:report);
    }
    else security_hole(port:get_kb_item("SMB/transport"));
    exit(0);
  }
  else if (ver[i] > fix[i]) break;
}

audit(AUDIT_INST_PATH_NOT_VULN, 'Sophos Anti-Virus', version, path);
