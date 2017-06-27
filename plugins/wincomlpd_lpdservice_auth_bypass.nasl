#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30187);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2008-5158");
  script_bugtraq_id(27614);
  script_osvdb_id(42862);

  script_name(english:"WinComLPD LPD Monitoring Server Authentication Bypass");
  script_summary(english:"Gets a list of remote printers");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by an authentication bypass
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote installation of WinComLPD fails to ensure that
authentication to its LPD Monitoring Server has been successful before
processing requests.  A remote attacker can leverage this issue to
bypass authentication and gain administrative control of the affected
application. 

Note that there are reportedly several other vulnerabilities
associated with this version of WinComLPD, including multiple buffer
overflows, although Nessus has not checked for them." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'WinComLPD Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_cwe_id(287);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/06");
 script_cvs_date("$Date: 2015/09/24 23:21:22 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("wincomlpd_lpdservice_detect.nasl");
  script_require_ports("Services/lpdservice", 13500);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item("Services/lpdservice");
if (!port) port = 13500;
if (!get_port_state(port)) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


# List remote printers.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

cmd = 0x0401;
req = 
  mkdword(0x65) +
  mkword(0) + 
  mkword(cmd) +
  mkdword(0);
send(socket:soc, data:req);
res = recv(socket:soc, length:1024, min:4);
close(soc);


# If the response looks right...
if (
  strlen(res) >= 12 &&
  getword(blob:res, pos:6) == (0x8000 + cmd) &&
  getword(blob:res, pos:8) == 0 &&
  (getword(blob:res, pos:10) + 12) == strlen(res)
)
{
  if (report_verbosity)
  {
    info = "";

    rc = getbyte(blob:res, pos:12);
    if (rc == 3) info = '  LPD Status         : activated\n';
    if (rc == 4) info = '  LPD Status         : de-activated\n';

    n = getbyte(blob:res, pos:13);
    info += '  Number of printers : ' + n + '\n';

    if (n > 0)
    {
      pos = 14;
      for (i=0; i<n && pos<strlen(res); i++)
      {
        l = getbyte(blob:res, pos:pos);
        printer = substr(res, pos+1, pos+1+l-1);
        pos += l+1;

        jobs = getdword(blob:res, pos:pos);
        pos += 4;

        status_flag = getbyte(blob:res, pos:pos);
        if (status_flag == 1) status = "Initial";
        else if (status_flag == 3) status = "Running";
        else if (status_flag == 4) status = "Paused";
        else if (status_flag == 5) status = "Stopped";
        else status = "unknown";
        pos += 1;

        l = getbyte(blob:res, pos:pos);
        comments = substr(res, pos+1, pos+1+l-1);
        pos += l+1;

        remote_flag = getbyte(blob:res, pos:pos);
        if (remote_flag == ord("1")) remote = "Remote";
        else if (remote_flag == ord("0")) remote = "Local";
        else remote = "unknown";
        pos += 1;

        info += '    Printer          : ' + printer + '\n' +
                '      Jobs           : ' + jobs + '\n' +
                '      Status         : ' + status + '\n' +
                '      Comments       : ' + comments + '\n' +
                '      Type           : ' + remote + '\n';
      }
    }

    report = string(
      "\n",
      "Nessus was able to discover the following information about the \n",
      "remote instance of WinComLPD :\n",
      "\n",
      info
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
