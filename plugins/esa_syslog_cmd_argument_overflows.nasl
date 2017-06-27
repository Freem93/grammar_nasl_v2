#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22127);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2006-3838");
  script_bugtraq_id(19165, 19167);
  script_osvdb_id(27525, 27527);
  script_xref(name:"Secunia", value:"21211");

  script_name(english:"eIQnetworks Enterprise Security Analyzer Syslog Server Multiple Remote Overflows");
  script_summary(english:"Tries to crash ESA Syslog Server with a long argument to DELETERDEPDEVICE command");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is vulnerable to remote
buffer overflow attacks." );
 script_set_attribute(attribute:"description", value:
"The version of eIQnetworks Enterprise Security Analyzer, Network
Security Analyzer, or one of its OEM versions installed on the remote
host is affected by multiple stack-based buffer overflows in its
Syslog Service.  Using a long argument to any of several commands, an
unauthenticated, remote attacker may be able to leverage this issue to
execute arbitrary code on the affected host with LOCAL SYSTEM
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.tippingpoint.com/security/advisories/TSRT-06-03.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/441200/30/90/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Enterprise Security Analyzer 2.1.14 / Network Security
Analyzer 4.5.4 / OEM software 4.5.4 or later" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'eIQNetworks ESA Topology DELETEDEVICE Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/07/25");
 script_cvs_date("$Date: 2017/02/23 16:41:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");
  script_dependencies("esa_syslog_detect.nasl");
  script_require_ports("Services/esa_syslog", 10617);
  exit(0);
}

#

include("global_settings.inc");


port = get_kb_item("Services/esa_syslog");
if (!port) port = 10617;
if (!get_port_state(port)) exit(0);


# If safe checks are enabled...
if (safe_checks())
{
  ver = get_kb_item("ESA/Syslog/"+port+"/Version");
  if (ver && "~" >< ver)
  {
    date = strstr(ver, "~") - "~";
    d = split(date, sep:'/', keep:FALSE);
    if (
      int(d[2]) < 2006 ||
      (
        int(d[2]) == 2006 &&
        (
          int(d[0]) < 7 ||
          (int(d[0]) == 7 && int(d[1]) < 26)
        )
      )
    )
    {
      report = string(
        "\n",
        "Nessus has used the build date, ", date, ", of the software on the\n",
        "remote host to determine that it is vulnerable to these issues.\n"
      );
      security_hole(port:port, extra:report);
    }
  }
}
# Otherwise...
else if (report_paranoia == 2)
{
  soc = open_sock_tcp(port);
  if (soc) 
  {
    # Try to exploit one of the flaws.
    #
    # nb: the form taken by the exploit depends on the command used.
    send(socket:soc, data:string("DELTAINTERVAL:", crap(3200)));
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
