#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(62947);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/30 21:51:49 $");

  script_bugtraq_id(56401);
  script_osvdb_id(87060, 87061);
  script_xref(name:"CERT", value:"662243");

  script_name(english:"Sophos Anti-Virus for Mac Multiple Vulnerabilities");
  script_summary(english:"Checks the product's version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has an antivirus application that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its engine version, the Sophos Anti-Virus installation on
the remote Mac OS X host is affected by multiple vulnerabilities :

  - A memory corruption issue exists in the RAR virtual
    machine standard filters.

  - A stack-based buffer overflow issue exists in the PDF
    file decrypter.");
  script_set_attribute(attribute:"see_also", value:"https://lock.cmpxchg8b.com/sophailv2.pdf");
  script_set_attribute(attribute:"see_also", value:"http://nakedsecurity.sophos.com/2012/11/05/tavis-ormandy-sophos/");
  script_set_attribute(attribute:"see_also", value:"http://www.sophos.com/en-us/support/knowledgebase/118424.aspx");
  script_set_attribute(attribute:"solution", value:"Upgrade to Sophos Anti-Virus engine version 3.37.10 or later.");
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
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("macosx_sophos_detect.nasl");
  script_require_keys("Antivirus/SophosOSX/installed", "MacOSX/Sophos/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Get the product version.
version = get_kb_item_or_exit("MacOSX/Sophos/EngineVersion");
path = get_kb_item_or_exit("MacOSX/Sophos/Path");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = split("3.37.10", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i < 3; i++)
{
  if ((ver[i] < fix[i]))
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Path                     : ' + path +
        '\n  Installed engine version : ' + version +
        '\n  Fixed engine version     : 3.37.10\n';
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
    exit(0);
  }
  else if (ver[i] > fix[i]) break;
}

audit(AUDIT_INST_PATH_NOT_VULN, 'Sophos Anti-Virus for Mac engine', version, path);
