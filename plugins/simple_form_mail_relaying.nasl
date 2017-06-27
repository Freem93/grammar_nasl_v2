#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


include("compat.inc");

if (description) {
  script_id(14224);
  script_version("$Revision: 1.15 $");
  script_bugtraq_id(10917);
  script_osvdb_id(8412);

# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, 09/2004)

  script_name(english:"Simple Form Multiple Parameter Arbitrary Mail Relaying");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that allows unauthorized
mail relaying." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of Simple Form, which fails
to validate the parameters 'admin_email_to' and 'admin_email_from'.

An attacker, exploiting this flaw, would be able to send email through
the server (utilizing the form) to any arbitrary recipient with any
arbitrary message content.  In other words, the remote host can be
used as a mail relay for things like SPAM." );
 script_set_attribute(attribute:"see_also", value:"http://worldcommunity.com/opensource/utilities/simple_form.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Simple Form 2.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/09");
 script_cvs_date("$Date: 2011/08/22 18:37:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for Mail Relaying Vulnerability in Simple Form";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2011 George A. Theall");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for mail relaying vulnerability in Simple Form on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check for the form in each of the CGI dirs.
foreach dir (cgi_dirs()) {
  if ( is_cgi_installed_ka(item:dir + "/s_form.cgi", port:port) )
   {
  url = string(dir, "/s_form.cgi");
  if (debug_level) display("debug: checking ", url, "...\n");

  # Exploit the form and *preview* the message to determine if the
  # vulnerability exists. Note: this doesn't actually try to inject
  # a message but should be fairly accurate.
  #
  # nb: both vulnerable and non-vulnerable versions of the script will 
  #     send a message if preview=no; the latter simply use hard-coded 
  #     values for admin_email_from and admin_email_to only when
  #     actually sending the message. Fortunately, we can identify
  #     vulnerable versions because they fail to filter newlines in
  #     form_email_subject.
  boundary = "bound";
  req = string(
    "POST ",  url, " HTTP/1.1\r\n",
    "Host: ", host, ":", port, "\r\n",
    "Referer: http://", host, "/\r\n",
    "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
    # nb: we'll add the Content-Length header and post data later.
  );
  boundary = string("--", boundary);
  postdata = string(
     boundary, "\r\n", 
    'Content-Disposition: form-data; name="form_response_title"', "\r\n",
    "\r\n",
    "A Response\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="form_return_url"', "\r\n",
    "\r\n",
    "http://", host, "/\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="form_return_url_title"', "\r\n",
    "\r\n",
    "Home\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="form_fields"', "\r\n",
    "\r\n",
    "msg\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="required_fields"', "\r\n",
    "\r\n",
    "msg\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="admin_email_from"', "\r\n",
    "\r\n",
    "postmaster@example.com\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="admin_email_to"', "\r\n",
    "\r\n",
    "postmaster@example.com\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="form_email_subject"', "\r\n",
    "\r\n",
    "Nessus Plugin Test\nBCC: postmaster@example.com\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="msg"', "\r\n",
    "\r\n",
    "This is a mail relaying test.\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="preview_data"', "\r\n",
    "\r\n",
    "yes\r\n",

    boundary, "--", "\r\n"
  );
  req = string(
    req,
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  if (debug_level) display("debug: sending =>>", req, "<<\n");
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);           # can't connect
  if (debug_level) display("debug: received =>>", res, "<<\n");

  # Look at the preview and see whether there's a BCC: header.
  if (
    egrep(string:res, pattern:"PREVIEW of Form Submission", icase:TRUE) &&
    egrep(string:res, pattern:"^BCC: ", icase:TRUE)
  ) {
    security_warning(port);
    exit(0);
  }
 }
}
