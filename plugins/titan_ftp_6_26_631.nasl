#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34434);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2008-6082");
  script_bugtraq_id(31757);
  script_osvdb_id(49177);
  script_xref(name:"EDB-ID", value:"6753");

  script_name(english:"Titan FTP Server SITE WHO Command Resource Consumption DoS");
  script_summary(english:"Checks version in banner or sends SITE WHO");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The version of Titan FTP Server installed on the remote host goes into
an unstable state when it receives a 'SITE WHO' command.  An
unauthenticated, remote attacker can leverage this issue to deny
service to legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://www.southrivertech.com/products/titanftp/verhist.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Titan FTP Server version 6.26, build 631 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_cwe_id(399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/16");
 script_cvs_date("$Date: 2016/05/19 18:02:20 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_MIXED_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("global_settings.inc");
include("ftp_func.inc");


port = get_ftp_port(default: 21);


# Make sure the banner looks like Titan FTP.
banner = get_ftp_banner(port:port);
if (!banner || " Titan FTP Server" >!< banner) exit(0);


if (safe_checks())
{
  # Identify the version.
  version = strstr(banner, " Titan FTP Server ") - " Titan FTP Server ";
  version = version - strstr(version, " Ready");

  if (version)
  {
    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (
      ver[0] < 6 ||
      (
        ver[0] == 6 && 
        (
          ver[1] < 26 ||
          (ver[1] == 26 && ver[2] < 631)
        )
      )
    )
    {
      if (report_verbosity)
      {
        version_ui = string(ver[0], ".", ver[1], " Build ", ver[2]);
        report = string(
          "\n",
          "Titan FTP ", version_ui, " appears to be running on the remote host.\n",
          "\n",
          "Note that Nessus did not actually try to exploit this issue because\n",
          "Safe Checks were enabled when the scan was run.\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
    }
  }
  exit(0);
}
else
{
  # Try to exploit the issue.
  soc = open_sock_tcp(port);
  if (!soc) exit(1);

  s = ftp_recv_line(socket:soc);

  send(socket:soc, data: 'SITE WHO\r\n');
  s = ftp_recv_line(socket:soc);

  # Try to reconnect, send a command, and get a response.
  for (iter=0; iter<5; iter++)
  {
    soc2 = open_sock_tcp(port);
    if (soc2)
    {
      s = ftp_recv_line(socket:soc2);
      if (s)
      {
        c = strcat('USER ', SCRIPT_NAME, '\r\n');
        send(socket:soc2, data: c);
        s = ftp_recv_line(socket:soc2);
        ftp_close(socket:soc2);
        if (s) exit(0);
      }
    }
    sleep(1);
  }
  security_warning(port);
}
