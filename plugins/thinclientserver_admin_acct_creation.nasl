#
# (C) Tenable Network Security
#

include("compat.inc");

if (description)
{
  script_id(23780);
  script_version ("$Revision: 1.14 $");

  script_cve_id("CVE-2006-6221");
  script_bugtraq_id(21300);
  script_osvdb_id(31841);

  script_name(english:"ThinClientServer Admin Account Creation Privilege Escalation");
  script_summary(english:"Tries to create an account in ThinClientServer");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows creation of
additional administrative accounts." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ThinClientServer, an application to convert
existing PCs into thin clients. 

The version of ThinClientServer installed on the remote host allows an
unauthenticated, remote attacker to create administrative accounts." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d0cb22c" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/11589" );
 script_set_attribute(attribute:"solution", value:
"It is reported that upgrading to ThinClientServer version 4.0.2248 or
higher addresses this issue.  You should also review the list of
existing administrators and remove any that are not valid." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/12/06");
 script_cvs_date("$Date: 2011/08/23 19:53:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 943, 980);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:980);
if (!can_host_php(port:port)) exit(0);


# Check whether the script exists.
url = "/enter.php?goto=%2F";
w = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(w)) exit(1, "the web server did not answer");
res = w[2];


# If ..
if (
  # the script does exist and...
  "<title>2X - Login" >< res &&
  # we can't ostensibly create an account.
  "name='dologin_new'" >!< res
)
{
  # Try to exploit the flaw to generate another administrative user.
  user = string("nessus-", rand_str());
  pass = rand();
  pass2 = string("not", pass);         # so we don't actually create the account.
  postdata = string(
    "username=", user, "&",
    "password=", pass, "&",
    "re_password=", pass2, "&",
    "dologin_new=OK&",
    "dologin=true"
  );
  w = http_send_recv3(method: "POST", item: url, port: port,
    content_type: "application/x-www-form-urlencoded",
    data: postdata );
  if (isnull(w)) exit(1, "the web server did not answer");

  # There's a problem if we get an error about passwords not matching.
  #
  # nb: in 4.0.2324, we just get "Bad Username or Password".
  if ("Passwords don&#039;t match" >< res) security_hole(port);
}
