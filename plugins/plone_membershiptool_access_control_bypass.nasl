#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21219);
  script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2014/08/09 00:11:24 $");

  script_cve_id("CVE-2006-1711");
  script_bugtraq_id(17484);
  script_osvdb_id(24582);

  script_name(english:"Plone Unprotected MembershipTool Methods Arbitrary Portrait Manipulation");
  script_summary(english:"Tries to change profiles using Plone");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Python application that is affected
by an access control failure." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Plone, an open source content manage system
written in Python.

The version of Plone installed on the remote host does not limit
access to the 'changeMemberPortrait' and 'deletePersonalPortrait'
MembershipTool methods.  An unauthenticated attacker can leverage this
issue to delete member portraits or add / update portraits with
malicious content." );
 script_set_attribute(attribute:"see_also", value:"http://dev.plone.org/plone/ticket/5432");
 script_set_attribute(attribute:"solution", value:
"Either install Hotfix 2006-04-10 1.0 or upgrade to Plone version 2.0.6
/ 2.1.3 / 2.5-beta2 when they become available." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/14");

 script_set_attribute(attribute:"cpe", value:"cpe:/a:plone:plone");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");

  script_dependencies("plone_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/plone");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# Get details of Plone install.
port = get_http_port(default:80);
install = get_install_from_kb(appname:"plone", port:port, exit_on_fail:TRUE);
dir = install["dir"];

url = dir + "/portal_membership/changeMemberPortrait";
r = http_send_recv3(
  method       : "GET",
  item         : url,
  port         : port,
  exit_on_fail : TRUE
);
res = r[2];

# If so...
if (
  '<meta name="generator" content="Plone' >< res &&
  "The parameter, <em>portrait</em>, was omitted from the request" >< res
)
{
  # Upload a profile for a nonexistent user.
  user = string(SCRIPT_NAME, "-", unixtime());
  portrait = rand_str();

  bound = "nessus";
  boundary = string("--", bound);
  postdata = string(
    boundary, "\r\n",
   'Content-Disposition: form-data; name="portrait"; filename="', user, '.gif"', "\r\n",
    "Content-Type: image/gif\r\n",
    "\r\n",
    portrait, "\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="member_id"', "\r\n",
    "\r\n",
    user, "\r\n",

    boundary, "--", "\r\n"
  );
  http_send_recv3(
    method       : "POST",
    item         : url,
    port         : port,
    content_type : "multipart/form-data; boundary=" + bound,
    data         : postdata,
    exit_on_fail : TRUE
  );

  # Retrieve the newly-created portrait.
  r = http_send_recv3(
    method       : "GET",
    item         : dir + "/portal_memberdata/portraits/" + user,
    port         : port,
    exit_on_fail : TRUE
  );
  res = r[2];

  # There's a problem if we get our portrait content back.
  if (portrait == res) security_warning(port);
}
