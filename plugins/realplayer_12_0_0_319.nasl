#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44119);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2009-0375", "CVE-2009-0376", "CVE-2009-4241", "CVE-2009-4242",
                "CVE-2009-4243", "CVE-2009-4244", "CVE-2009-4245", "CVE-2009-4246",
                "CVE-2009-4247", "CVE-2009-4248", "CVE-2009-4257");
  script_bugtraq_id(33652, 37880);
  script_osvdb_id(
    54297,
    54298,
    61965,
    61966,
    61967,
    61968,
    61969,
    61970,
    61971,
    61972,
    61973
  );
  script_xref(name:"Secunia", value:"38218");
  script_xref(name:"IAVA", value:"2010-A-0022");

  script_name(english:"RealPlayer for Windows < Build 12.0.0.319 Multiple Buffer Overflows");
  script_summary(english:"Checks RealPlayer build number.");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows application is affected by multiple buffer
overflow vulnerabilities."
  );
  script_set_attribute(attribute:"description",value:
"According to its build number, the installed version of RealPlayer on
the remote Windows host has multiple buffer overflow vulnerabilities :

  - A RealPlayer 'ASM' Rulebook heap-based overflow. 
    (CVE-2009-4241)

  - A RealPlayer 'GIF' file heap overflow. (CVE-2009-4242)

  - A RealPlayer media overflow ('http' chunk encoding).
    (CVE-2009-4243)

  - A RealPlayer 'IVR' file processing buffer overflow.
    (CVE-2009-0375)

  - A RealPlayer 'IVR' file heap overflow. (CVE-2009-0376)

  - A RealPlayer 'SIPR' codec heap overflow. (CVE-2009-4244)

  - A RealPlayer compressed 'GIF' heap overflow. 
    (CVE-2009-4245)

  - A RealPlayer 'SMIL' parsing heap overflow. 
    (CVE-2009-4257)

  - A RealPlayer skin parsing stack overflow. 
    (CVE-2009-4246)

  - A RealPlayer 'ASM' RuleBook Array Overflow. 
    (CVE-2009-4247)

  - A RealPlayer 'rtsp' set_parameter buffer overflow.
    (CVE-2009-4248)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/509100/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/509096/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/509105/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/509098/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/509104/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/509286/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/509288/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/509293/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/01192010_player/en/");

  script_set_attribute(attribute:"solution", value:"Upgrade to RealPlayer SP 1.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"vuln_publication_date",value:"2010/01/19");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/01/19");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/01/22");
 script_cvs_date("$Date: 2016/12/09 20:54:57 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("realplayer_detect.nasl");
  script_require_keys("SMB/RealPlayer/Product", "SMB/RealPlayer/Build");

  exit(0);
}

include("global_settings.inc");

prod = get_kb_item("SMB/RealPlayer/Product");
if (!prod) exit(1, "The 'SMB/RealPlayer/Product' KB item is missing.");

build = get_kb_item("SMB/RealPlayer/Build");
if (!build) exit(1, "The 'SMB/RealPlayer/Build' KB item is missing.");

ver = split(build, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

vuln = FALSE;
if ("RealPlayer" == prod)
{
  # nb: build numbers ARE NOT NECESSARILY SEQUENTIAL!
  if 
  (
    ver[0] < 6 ||
    (
      ver[0] == 6 && ver[1] == 0 &&
      (
        ver[2] < 12 ||
        (
          (
            ver[2] == 12 &&
            (
              (ver[3] >= 1040 && ver[3] <= 1663) ||
              ver[3] == 1675 ||
              ver[3] == 1698 ||
              ver[3] == 1741
            )
          ) ||
          ver[2] == 14
        ) 
      )
    )
  ) vuln=TRUE;
}
else if ("RealPlayer SP" == prod)
{
  if (ver[0] == 12 && ver[1] == 0 && ver[2] == 0 && ver[3] < 319) vuln=TRUE;
}
if ("RealPlayer" == prod || "RealPlayer SP" == prod)
{
  if (vuln)
  {
    if (report_verbosity > 0)
    {
      report = 
        '\n' +
        prod + ' build ' + build + ' is installed on the remote host.\n'+
        '\n';
      security_hole(port:get_kb_item("SMB/transport"), extra:report);
    }
    else security_hole(get_kb_item("SMB/transport"));
    exit(0);
  }
  else exit(0, 'The host is not affected because '+prod+' build '+build+' was detected.');
}
