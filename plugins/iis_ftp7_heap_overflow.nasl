#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51956);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/01/14 15:43:29 $");

  script_cve_id("CVE-2010-3972");
  script_bugtraq_id(45542);
  script_osvdb_id(70167);
  script_xref(name:"EDB-ID", value:"15803");
  script_xref(name:"MSFT", value:"MS11-004");

  script_name(english:"MS11-004: Vulnerability in Internet Information Services (IIS) FTP Service Could Allow Remote Code Execution (2489256) (uncredentialed check)");
  script_summary(english:"Checks for IIS FTP Service heap overflow vulnerability");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The FTP service running on the remote host has a memory corruption
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The IIS FTP service running on the remote host has a heap-based buffer
overflow vulnerability.  The 'TELNET_STREAM_CONTEXT::OnSendData'
function fails to properly sanitize user input, resulting in a buffer
overflow.

An unauthenticated, remote attacker can exploit this to execute
arbitrary code."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-004");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows Vista, 2008, 2008
R2, and 7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");


port = get_ftp_port(default:21);

soc = open_sock_tcp(port);
if (!soc) exit(1, "Failed to open a socket on port "+port+".");

banner =  ftp_recv_line(socket:soc);
if ( isnull(banner) ) exit(1, "Could not retrieve the banner from the FTP server on port "+port+".");

if (banner !~ "^22. *Microsoft FTP Service")
  exit(0, "The FTP service on port "+port+" does not appear to be Microsoft FTP.");


data = crap(data:'A', length:4090);
data += raw_string(0xff,0xff);
data += crap(data:'B', length:8);

send(socket:soc, data:data);

res = ftp_recv_line(socket:soc);
if (isnull(res)) exit(1,"The FTP service on port "+port+" did not respond.");

# vulnerable
if(res =~ '^01 *\'A{4090}\xff\xffB{5}')
  security_hole(port);
# patched
else if (res =~'^501 *\'A{4090}\xffB{5}')
  exit(0,"The Microsoft FTP service on port "+port+" is patched.");
# FTP 6.0 on vista_sp1_x86 and win2008_sp1_x64 returned "421 Terminating connection."
else if(res =~ "Terminating connection")
  exit(0,"The FTP service on port "+port+" is not affected (possibly Microsoft FTP Service 6.0).");
# FTP 5.1 on xp_sp3_x86 returned "500 Command was too long"
else if(res =~ "Command was too long")
  exit(0,"The FTP service on port "+port+" is not affected (possibly Microsoft FTP Service 5.1).");
else exit(1,'The FTP service on port "+port+" sent an unexpected return ('+res+').');
