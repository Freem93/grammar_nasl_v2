#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22129);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-3838");
  script_bugtraq_id(19163);
  script_osvdb_id(27526);
  script_xref(name:"Secunia", value:"21211");

  script_name(english:"eIQnetworks Enterprise Security Analyzer EnterpriseSecurityAnalyzer.exe LICMGR_ADDLICENSE Command Remote Overflow");
  script_summary(english:"Tries to crash ESA license manager with a long LICMGR_ADDLICENSE command");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is vulnerable to a remote
buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The version of eIQnetworks Enterprise Security Analyzer, Network
Security Analyzer, or one of its OEM versions installed on the remote
host contains a buffer overflow in its License Manager service.  Using
a long argument to the 'LICMGR_ADDLICENSE' command, an unauthenticated
remote attacker may be able to leverage this issue to execute
arbitrary code on the affected host with LOCAL SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-06-024.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/441195/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Enterprise Security Analyzer 2.1.14 / Network Security
Analyzer 4.5.4 / OEM software 4.5.4 or later" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'eIQNetworks ESA Topology DELETEDEVICE Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/07/25");
 script_cvs_date("$Date: 2011/03/11 21:52:32 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
  script_dependencies("esa_licmgr_detect.nasl");
  script_require_ports("Services/esa_licmgr", 10616);

  exit(0);
}


include("global_settings.inc");


port = get_kb_item("Services/esa_licmgr");
if (!port) port = 10616;
if (!get_port_state(port)) exit(0);


# If safe checks are enabled...
if (safe_checks())
{
  build = get_kb_item("ESA/Licmgr/"+port+"/Version");
  if (build)
  {
    # Look at the product and build number.
    pat = "^([^ ]+) +v([0-9][^ ]+) +([^ ]+)";
    m = eregmatch(pattern:pat, string:build);
    if (m)
    {
      prod = m[1];
      ver = m[2];
      vuln = 0;
      if (prod == "ESA")
      {
        v = split(ver, sep:'.', keep:FALSE);
        if (
          int(v[0]) < 2 ||
          (
            int(v[0]) == 2 &&
            (
              int(v[1]) < 1 ||
              (int(v[1]) == 1 && int(v[2]) < 14)
            )
          )
        ) vuln = 1;
      }
      else
      {
        v = split(ver, sep:'.', keep:FALSE);
        if (
          int(v[0]) < 4 ||
          (
            int(v[0]) == 4 &&
            (
              int(v[1]) < 5 ||
              (int(v[1]) == 5 && int(v[2]) < 4)
            )
          )
        ) vuln = 1;
      }

      if (vuln)
      {
        report = string(
          "\n",
          "Nessus has used the build version, ", ver, ", of the software on the\n",
          "remote host to determine that it is vulnerable to these issues.\n"
        );
        security_hole(port:port, extra:report);
      }
    }
  }
}
# Otherwise...
else if (report_paranoia == 2)
{
  soc = open_sock_tcp(port);
  if (soc) 
  {
    send(socket:soc, data:string("LICMGR_ADDLICENSE ", crap(1500)));
    res = recv(socket:soc, length:64);
    close(soc);

    # If we didn't get a response...
    if (isnull(res)) 
    {
      # Try to reconnect.
      soc2 = open_sock_tcp(port);
      if (!soc2) security_hole(port);
      else close(soc2);
    }
  }
}
