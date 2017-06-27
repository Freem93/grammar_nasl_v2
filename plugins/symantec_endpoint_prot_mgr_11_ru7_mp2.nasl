#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59366);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2012-0289", "CVE-2012-1821");
  script_bugtraq_id(50358, 51795);
  script_osvdb_id(82147, 82149);
  script_xref(name:"CERT", value:"149070");
  script_xref(name:"EDB-ID", value:"18916");

  script_name(english:"Symantec Endpoint Protection Manager < 11 RU7 MP2 (SYM12-007 / SYM12-008) (credentialed check)");
  script_summary(english:"Checks SEP version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The endpoint management application installed on the remote Windows
host has multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Symantec Endpoint Protection Manager installed on the
remote host is less than 11 RU7 MP2 (11.7.7200) and has the following
vulnerabilities :

  - A denial of service vulnerability exists that could 
    cause the web server to stop serving pages and, in some
    cases, crash the server.  This vulnerability is only 
    present on Windows 2003 systems with SP2 or below. 
    (CVE-2012-1821)

  - A buffer overflow exists that could allow a local 
    attacker to elevate privileges. (CVE-2012-0289)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-145/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/265");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120522_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16ddf0c0");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120522_01
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b4a63b4");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Symantec Endpoint Protection 11 RU7 MP2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_endpoint_prot_mgr_installed.nasl");
  script_require_keys("SMB/sep_manager/path", "SMB/sep_manager/ver");

  exit(0);
}

include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

port = kb_smb_transport();
path = get_kb_item_or_exit('SMB/sep_manager/path');
display_ver = get_kb_item_or_exit('SMB/sep_manager/ver');
ver = split(display_ver, sep:'.', keep:FALSE);

if (ver[0] == 11 && ver[1] == 0 && (ver[2] < 7200 || (ver[2] == 7200 && ver[3] < 174)))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : 11.0.7200.174 (11 RU7 MP2)\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'SEP', display_ver);
