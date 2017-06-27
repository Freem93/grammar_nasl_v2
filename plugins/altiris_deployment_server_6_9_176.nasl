#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32323);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2008-2286","CVE-2008-2287","CVE-2008-2288","CVE-2008-2289","CVE-2008-2291");
  script_bugtraq_id(29196, 29197, 29198, 29199, 29218);
  script_osvdb_id(45313, 45314, 45315, 45316, 45317, 45318);
  script_xref(name:"Secunia", value:"30261");

  script_name(english:"Altiris Deployment Solution < 6.9.176 Multiple Vulnerabilities");
  script_summary(english:"Checks deployment server version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of the Altiris Deployment Solution installed on the remote
host reportedly is affected by several issues :

  - A SQL injection vulnerability that could allow a user
    to run arbitrary code (CVE-2008-2286).

  - A remote attacker may be able to obtain encrypted 
    Altiris Deployment Solution domain credentials without 
    authentication (CVE-2008-2291).

  - A local user could leverage a GUI tooltip to access a
    privileged command prompt (CVE-2008-2289).

  - A local user can modify or delete several registry keys
    used by the application, resulting in unauthorized 
    access to system information or disruption of service
    (CVE-2008-2288).

  - A local user with access to the install directory of
    Deployment Solution could replace application 
    components, which might then run with administrative 
    privileges on an affected system (CVE-2008-2287)." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/May/196" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/May/198" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-024" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-025" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/May/176" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/May/177" );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2008.05.14a.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Altiris Deployment Solution 6.9.176 or later and update
Agents." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Symantec Altiris DS SQL Injection');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(89, 255, 264);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/15");
 script_cvs_date("$Date: 2016/11/11 19:58:29 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("altiris_deployment_server_detect.nasl");
  script_require_ports("Services/axengine", 402);
  exit(0);
}

#

include("global_settings.inc");



port = get_kb_item("Services/axengine");
if (!port) port = 402;
if (!get_port_state(port)) exit(0);


# Make sure the port is really open.
soc = open_sock_tcp(port);
if (!soc) exit(0);
close(soc);


# Check the version.
version = get_kb_item("Altiris/DSVersion/"+port);
if (!isnull(version))
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fix = split("6.9.176", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        version = string(ver[0], ".", ver[1], ".", ver[2]);
        report = string(
          "\n",
          "Version ", version, " of the Altiris Deployment Solution is installed on\n",
          "the remote host.\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
