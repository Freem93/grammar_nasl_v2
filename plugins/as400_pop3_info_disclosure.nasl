#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18046);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2005-1133");
  script_bugtraq_id(13156);
  script_osvdb_id(15510);

  script_name(english:"IBM AS400 and iSeries POP3 Server Remote Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote POP server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running the POP3 service that comes with
all modern AS/400 and iSeries servers.  Further, this service is prone
to an information disclosure vulnerability due to the responses it
provides to username / password combinations.  This allows a remote
attacker to determine valid user profiles.  Further, the service
offers a means of brute forcing passwords since it does not block a
connection or disable a user after a given number of invalid login
attempts." );
 script_set_attribute(attribute:"see_also", value:"http://www.venera.com/downloads/Enumeration_of_AS400_users_via_pop3.pdf" );
 script_set_attribute(attribute:"solution", value:
"Disable the POP3 service if not needed." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/15");
 script_cvs_date("$Date: 2016/05/04 14:21:28 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for remote information disclosure vulnerability in IBM AS400 and iSeries POP3 server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencie("find_service1.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/pop3", 110);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("pop3_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
port = get_service(svc: "pop3", default: 110, exit_on_fail: 1);

if (get_kb_item("pop3/"+port+"/false_pop3")) exit(0);

banner = get_pop3_banner(port:port);
if ( ! banner || "+OK POP3 server ready" >!< banner ) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read banner.
s = recv_line(socket:soc, length:1024);
if (!strlen(s) || "+OK POP3 server ready" >!< s ) {
  close(soc);
  exit(0);
}
s = chomp(s);


# Try various ways to log in.
i=-1;
# - real account.
users[++i] = "qsysopr";
result[i] = "ERR .+ CPF22E2";
# - bogus user; eg, "030757"
now = split(gettimeofday(), sep:".", keep:0);
users[++i] = now[1];
result[i] = "ERR .+ CPF2204";
# - real account but w/o password
users[++i] = "qspl";
result[i] = "ERR .+ CPF22E5";

matches = 0;
foreach i (keys(users)) {
  send(socket:soc, data: 'USER '+i+'\r\n\r\n');
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = "";
  }
  if (resp && "OK" >< resp) {
    send(socket:soc, data: 'PASS nessus\r\n');
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        if (egrep(string:s, pattern:result[i])) ++matches;
        break;
      }
      resp = "";
    }
  }
}


# If the result of each login attempt matched the expected pattern,
# there's a problem.
if (matches == i) security_warning(port);


# Logout.
send(socket:soc, data: 'QUIT\r\n');
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = "";
}
close(soc);
