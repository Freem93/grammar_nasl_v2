#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58724);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/06/23 19:16:51 $");

  script_cve_id(
    "CVE-2012-0942",
    "CVE-2012-1923",
    "CVE-2012-1984",
    "CVE-2012-1985",
    "CVE-2012-2267",
    "CVE-2012-2268"
  );
  script_bugtraq_id(52929);
  script_osvdb_id(81053, 81054, 81055, 81056, 81057, 81058);
  script_xref(name:"IAVB", value:"2012-B-0043");
  script_xref(name:"Secunia", value:"45414");

  script_name(english:"RealNetworks Helix Server 14.x < 14.3.x Multiple Vulnerabilities");
  script_summary(english:"Checks version in banner.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote media streaming server is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote host is running version 14.x of
RealNetworks Helix Server / Helix Mobile Server.  Such versions are
potentially affected by multiple vulnerabilities :

  - Administrative and user credentials are insecurely 
    stored in a flat file database.  This file may be 
    accessed by local users to disclose passwords stored in
    plaintext. (CVE-2012-1923)

  - A buffer overflow exists in the code that parses 
    authentication credentials. It may be possible for a 
    remote attacker to exploit this issue and execute 
    arbitrary code. (CVE-2012-0942)

  - Multiple unspecified cross-site scripting 
    vulnerabilities. (CVE-2012-1984)

  - A specially crafted malformed URL can cause the server 
    process to crash if opened by an administrator. 
    (CVE-2012-1985)

  - Establishing and immediately closing a TCP connection on 
    port 705 can cause the SNMP Master Agent to crash.
    (CVE-2012-2267)

  - A specially crafted Open-PDU request sent to the SNMP 
    Master Agent can cause it to crash due to an unhandled 
    exception. (CVE-2012-2268)"
  );
  script_set_attribute(attribute:"see_also",value:"http://secunia.com/secunia_research/2012-8/");
  script_set_attribute(attribute:"see_also",value:"http://secunia.com/secunia_research/2012-9/");
  script_set_attribute(attribute:"see_also",value:"http://www.securityfocus.com/archive/1/522249/30/0/threaded");
  script_set_attribute(attribute:"see_also",value:"http://www.securityfocus.com/archive/1/522250/30/0/threaded");
  script_set_attribute(attribute:"see_also",value:"http://helixproducts.real.com/docs/security/SecurityUpdate04022012HS.pdf");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to RealNetworks Helix Server / Helix Mobile Server 14.3.x or
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date",value:"2012/04/09");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/12");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:realnetworks:helix_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("rtsp_detect.nasl");
  script_require_ports("Services/rtsp", 554);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

port = get_service(svc:"rtsp", exit_on_fail:TRUE);

serv = get_kb_item_or_exit("rtsp/server/"+port);

if (!ereg(pattern:"Helix (Mobile|) *Server Version", string:serv))
  exit(0, "The banner from the RTSP service on port "+port+" is not from Helix Server or Helix Mobile Server.");

matches = eregmatch(pattern:"Server Version ([0-9\.]+)", string:serv);
if (!matches) exit(1, "Nessus failed to extract the version from the banner of Helix server listening on port "+port+".");

version = matches[1];

# 14.x < 14.3.x is vulnerable
if (ereg(pattern:"^14\.[0-2]\.", string:version))
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + serv + 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 14.3.x' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Helix server", port, version);
