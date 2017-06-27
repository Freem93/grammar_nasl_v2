#
# (C) Tenable Network Security, Inc.
# 

include("compat.inc");

if (description)
{
  script_id(63265);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2012-3274");
  script_bugtraq_id(55271);
  script_osvdb_id(85060);

  script_name(english:"HP Intelligent Management Center User Access Manager Datagram Parsing Code Execution");
  script_summary(english:"Checks version of HP IMC UAM");
  
  script_set_attribute(attribute:"synopsis", value:
"The remote host has a user access management application installed that
is affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the HP Intelligent Management Center
User Access Manager installed on the remote host is affected by a
stack-based buffer overflow vulnerability.  By sending a specially
crafted datagram, a remote, unauthenticated attacker could execute
arbitrary code on the remote host subject to the privileges of the user
running the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-171/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Dec/46");
  # https://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03589863-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1dfcffd9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Intelligent Management Center User Access Manager 5.1 SP1
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP Intelligent Management Center UAM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/14");
  
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_imc_detect.nbin");
  script_require_ports("Services/activemq", 61616);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Figure out which port to user
port = get_service(svc:'activemq', default:61616, exit_on_fail:TRUE);

version = get_kb_item_or_exit('hp/hp_imc/'+port+'/components/iMC-UAM/version');

# All versions before 5.1-E0101P01 are affected
if (version =~ '^([0-4]\\.|5\\.(0|1([^\\-]|-E0101([^P]|$|P00($|[^0-9])))))')
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.1-E0301P03' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'HP Intelligent Management Center User Access Manager', port, version); 
