#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(58516);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2011-3165", "CVE-2011-3166", "CVE-2011-3167");
  script_bugtraq_id(50471, 51049);
  script_osvdb_id(76773, 76774, 76775);

  script_name(english:"HP OpenView Network Node Manager Multiple Code Execution Vulnerabilities (HPSBMU02712 SSRT100649)");
  script_summary(english:"Checks NNM version & patch level");
  
  script_set_attribute(attribute:"synopsis", value:
"The version of HP Network Node Manager running on the remote host is
affected by multiple code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of HP Network Node Manager is affected by the
following vulnerabilities :

  - A remote code execution vulnerability exists because
    the 'nnmRptConfig.exe' CGI application does not
    adequately validate user-supplied input. (CVE-2011-3165)

  - A remote code execution vulnerability exists within
    ov.dll. Insufficient boundary checking before supplying
    the value to a format string within _OVBuildPath can
    cause a stack overflow, leading to memory corruption,
    which could allow an attacker to execute arbitrary code
    within the context of the target service. (CVE-2011-3166)

  - A remote code execution vulnerability exists within the
    webappmon.exe CGI program. The vulnerability is due an
    insufficient boundary check before supplying a format
    string with the values. This causes a stack overflow,
    which can lead to memory corruption that can be
    exploited to execute arbitrary code within the context
    of the target service. (CVE-2011-3167)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-348/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-002/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-003/");
   # https://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03054052-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78ad040f");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/520349");

  script_set_attribute(attribute:"solution", value:"Upgrade to B.07.53 Patchlevel NNM_01213 or its equivalent.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP OpenView Network Node Manager ov.dll _OVBuildPath Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/28");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:openview_network_node_manager");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:openview_network_node_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");

  script_dependencies('hp_nnm_detect.nbin');
  script_require_keys('hp/hp_nnm');
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Get the port number
port = get_http_port(default:7510);

# Get the version number and patch info
version = get_kb_item_or_exit('hp/hp_nnm/'+port+'/version');
if (version !~ "^[A-Z]+\.[0-9]+\.[0-9]+$") exit(1, "The version of Network Node Manager listening on port "+port+" is not recognized ("+version+").");
version_split = split(version, sep:'.', keep:FALSE);

patchlevel = get_kb_item('hp/hp_nnm/'+port+'/patchlevel');

# Versions before B.07.53 are vulnerable, as are B.07.53 before NMM_01213
if (
  version_split[0] == 'B' && 
  int(version_split[1]) == 7 &&
  (
    int(version_split[2]) < 53 ||
    (int(version_split[2]) == 53 && (isnull(patchlevel) || patchlevel < 'NNM_01213'))
  )
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version;
    if (!isnull(patchlevel)) report += ' ' + patchlevel + ' (or equivalent)';
    report += '\n  Fixed version     : B.07.53 Windows                => NNM_01213' +
              '\n                              Solaris                => PSOV_03535' +
              '\n                              Linux RedHatAS2.1      => LXOV_00121' +
              '\n                              Linux RedHat4AS-x86_64 => LXOV_00122' +
              '\n                              HP-UX (IA)             => PHSS_42233' +
              '\n                              HP-UX (PA)             => PHSS_42232' +
              '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else 
{
  errmsg = "The Network Node Manager " + version + " ";
  if (!isnull(patchlevel)) errmsg += patchlevel + " (or equivalent) ";
  errmsg += " install listening on port "+port+" is not affected.";
  exit(0, errmsg);
}
