#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38198);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2009-1075", "CVE-2009-1076");
  script_bugtraq_id(34191);
  script_osvdb_id(53162, 53163);
  script_xref(name:"Secunia", value:"34380");

  script_name(english:"Sun Java System Identity Manager Account Disclosure");
  script_summary(english:"Checks if the application is leaking information");

  script_set_attribute( attribute:"synopsis", value:
"The remote host is running a web application with information
disclosure vulnerabilities."  );
  script_set_attribute( attribute:"description",  value:
"The version of Sun Java System Identity Manager running on the remote
host has the following account enumeration vulnerabilities :

- The error message for a failed login attempt is different,
  depending on whether or not a valid username was given.

- Requesting IDMROOT/questionLogin.jsp?accountId=USERNAME results in
  different results, depending on whether USERNAME is valid.

A remote attacker could use these to enumerate valid usernames,
which could be used to mount further attacks.

There are also other issues known to be associated with this version
of Identity Manager that Nessus has not tested for. Refer to Sun
Security Alert #253267 for more information."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://blogs.sun.com/security/entry/sun_alert_253267_sun_java"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.oracle.com/sunalerts/1020159.1.html"
  );
  script_set_attribute( attribute:"solution", value:
"The vendor has made a patch available. It fixes other unrelated
vulnerabilities, but only partially addresses this issue. At this
time, there is no known comprehensive solution."  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 255);
 script_set_attribute(attribute:"patch_publication_date", value: "2009/03/19");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/28");
 script_cvs_date("$Date: 2016/12/14 20:33:27 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("sun_idm_detect.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


fake_user = string(SCRIPT_NAME, "-", unixtime());

port = get_http_port(default:80, embedded: 0);

# Only does the check if Sun IDM was already detected on the remote host
install = get_kb_item(string("www/", port, "/sun_idm"));
if (isnull(install)) exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");

if (!isnull(matches))
{
  dir = matches[2];

  # Tries to get prompted for the security question of a nonexistent user.
  url = string(dir, "/questionLogin.jsp?accountId=", fake_user);
  res = http_send_recv3(
    method:"GET",
    item:url,
    port:port,
    follow_redirect:1
  );

  if (isnull(res)) exit(0);

  # If the server explicitly says the user does not exist,
  # this host is vulnerable
  if ('The specified user was not found.' >< res[2])
  {
    security_warning(port);
    exit(0);
  }

  # If the 'Forgot Password' method didn't leak information, see if
  # logging in as a nonexistent user will
  url = string(dir, "/login.jsp");
  postdata = 'command=login&accountId=' + fake_user;
  res = http_send_recv3(
    method:"POST",
    item:url,
    port:port,
    data:postdata,
    add_headers : make_array(
      "Content-Type", "application/x-www-form-urlencoded"
    )
  );

  if (isnull(res)) exit(0);

  if ('Invalid Account ID' >< res[2]) security_warning(port);
}

