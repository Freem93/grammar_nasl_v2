#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42978);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/05/01 17:21:54 $");

  script_name(english:"DNN (DotNetNuke) Detection");
  script_summary(english:"Checks for the presence of DNN.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application framework written in
ASP.NET.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running DNN (formerly known as DotNetNuke),
a web application framework written in ASP.NET.

Note that this plugin can attempt to log into the application and
obtain version information if supplied with credentials for a user
with superuser privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.dnnsoftware.com");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP", "http/login");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("url_func.inc");

app = "DNN";
port = get_http_port(default:80, asp:TRUE);

if (thorough_tests)
  dirs = list_uniq(make_list("/dotnetnuke", "/dnn", cgi_dirs()));
else
  dirs = make_list(cgi_dirs());

# This function is used for logging into DNN instances and obtaining
# version information for the Host Settings tab.  The login must be that
# of a superuser user account.
# Function requires that you pass in dir (directory) and port parameters
function dnn_login(port, dir)
{
  if (isnull(dir) || isnull(port)) return NULL;
  if (!get_kb_item("http/login")) return NULL;

  local_var login_page, login, boundary, viewstate_pat, validation_pat,
    exit_message, user, pass, login_page1, login_page2, login_page3, res,
    viewstate, validation, match, dnn3url, dnn2url, dnn1url, postdata,
    res2, viewstate_enc, validation_enc, pats, pattern, dashboard,
    dash_link, link, pos, line, res3, ver_str, output, matches, version,
    i, ver, disp_ver;

  clear_cookiejar();
  user = get_kb_item("http/login");
  pass = get_kb_item("http/password");

  login_page = FALSE;
  login_page1 = FALSE;
  login_page2 = FALSE;
  login_page3 = FALSE;
  login = FALSE;
  boundary = '-----------------------------xxxxxxxxxxxxx';
  viewstate_pat = 'id="__VIEWSTATE" value="(.+)"';
  validation_pat = 'id="__EVENTVALIDATION" value="(.+)"';

  # With several POST requests, we want to ensure we don't timeout and
  # have a false negative
  http_set_read_timeout(get_read_timeout() * 2);

  # Check for login page for versions 4.x, 5.x, 6.x, 7.x
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + "/login.aspx",
    exit_on_fail : TRUE
  );

  if (
    'User Log In' >< res[2] &&
    'dnn_ctr_Login_Login_DNN_txtPassword' >< res[2]
  )
  {
    login_page = TRUE;

    viewstate = eregmatch(pattern:viewstate_pat, string:res[2]);
    if (!isnull(viewstate))
      viewstate = viewstate[1];

    validation = eregmatch(pattern:validation_pat, string:res[2]);
    if (!isnull(validation))
      validation = validation[1];
  }

  # Grab login page URL for versions 3.x
  if (!login_page)
  {
    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : dir + "/Default.aspx",
      exit_on_fail : TRUE
    );

    if ("dnn_dnnLOGIN_hypLogin" >< res[2])
    {
      match = eregmatch(
        pattern : 'dnn_dnnLOGIN_hypLogin" class="SkinObject" href=(.+)' +
                  '(/Home/.+)"\\>Login',
        string  : res[2]
      );
      if (!isnull(match))
      {
        dnn3url = match[2];
        login_page3 = TRUE;
      }
    }
  }

  # Grab login page URL for versions 2.x
  if ( (!login_page) && (!login_page3) )
  {
    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : dir + "/Default.aspx",
      exit_on_fail : TRUE
    );

    if ("_ctl0_dnnLogin_hypLogin" >< res[2])
    {
      match = eregmatch(
        pattern :'_ctl0_dnnLogin_hypLogin" class="OtherTabs" href="(.+)"\\>Login',
        string  : res[2]
      );
      if (!isnull(match))
      {
        dnn2url = "/" + match[1];
        dnn2url = str_replace(string:dnn2url, find:"&amp;", replace:"&");
        login_page2 = TRUE;
      }
    }
  }

  # Grab login page URL for versions 1.x
  if ( (!login_page) && (!login_page2) && (!login_page3) )
  {
    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : dir + "/Default.aspx",
      exit_on_fail : TRUE
    );

    if ("Banner_hypLogin" >< res[2])
    {
      match = eregmatch(
        pattern : 'Banner_hypLogin" class="OtherTabs" href="(.+)">Login',
        string  : res[2]
      );
      if (!isnull(match))
      {
        dnn1url = "/" + match[1];
        dnn1url = str_replace(string:dnn1url, find:"&amp;", replace:"&");
        login_page1 = TRUE;
      }
    }
  }

  # Exit if we cannot obtain a login page
  if ( (!login_page) && (!login_page1) && (!login_page2) && (!login_page3) )
    return NULL;

  if (login_page)
  {
    # If we don't have our viewstate and validation values, then our POST
    # request will fail.  Version 4.x and up require viewstate
    if ( (isnull(viewstate)) && (isnull(validation)) ) return NULL;

    # Versions 9.x
    boundary = '-----------------------------xxxxxxxxxxxxx';
    postdata = boundary + '\n' +
      'Content-Disposition: form-data; name="StylesheetManager_TSSM"\n'+
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="ScriptManager_TSM"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__EVENTTARGET"\n' +
      '\n' + 'dnn$ctr$Login$Login_DNN$cmdLogin\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__EVENTARGUMENT"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__VIEWSTATE"\n' +
      '\n' + viewstate + '\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__VIEWSTATEGENERATOR"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__VIEWSTATEENCRYPTED"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__EVENTVALIDATION"\n' +
      '\n' + validation + '\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="dnn$ctr$Login$Login_DNN$txtUsername"\n' +
      '\n' + user + '\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="dnn$ctr$Login$Login_DNN$txtPassword"\n' +
      '\n' + pass + '\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="dnn$ctr$Login$Login_DNN$chkCookie"\n' +
      '\noff\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="ScrollTop"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__dnnVariable"\n' +
      '\n' +
      '`{`__scdoff`:`1`}\n' +
      boundary + '--';

    res2 = http_send_recv3(
      method : "POST",
      item   : dir + "/Login",
      data   : postdata,
      port   : port,
      add_headers  : make_array("Content-Type",
      "multipart/form-data; boundary=---------------------------xxxxxxxxxxxxx"),
      exit_on_fail : TRUE,
      follow_redirect : 2
    );

    if (
      ('id="dnn_dnnLogin_loginGroup"' >< res2[2]) &&
      ('id="dnn_dnnLogin_enhancedLoginLink" title="Logout"' >< res2[2])
    )
    {
      login = TRUE;
    }

    # Versions 7.x
    boundary = '-----------------------------xxxxxxxxxxxxx';
    postdata = boundary + '\n' +
      'Content-Disposition: form-data; name="StylesheetManager_TSSM"\n'+
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="ScriptManager_TSM"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__EVENTTARGET"\n' +
      '\n' + 'dnn$ctr$Login$Login_DNN$cmdLogin\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__EVENTARGUMENT"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__VIEWSTATE"\n' +
      '\n' + viewstate + '\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__VIEWSTATEENCRYPTED"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__EVENTVALIDATION"\n' +
      '\n' + validation + '\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="dnn$dnnSearch$txtSearch"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="dnn$ctr$Login$Login_DNN$txtU' +
      'sername"\n' +
      '\n' + user + '\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="dnn$ctr$Login$Login_DNN$txtPas' +
      'sword"\n' +
      '\n' + pass + '\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="ScrollTop"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__dnnVariable"\n' +
      '\n' +
      '{"__scdoff":"1","__dnn_pageload":"__dnn_SetInitialFocus(\\u0027dnn_ctr' +
      '_Login_Login_DNN_txtUsername\\u0027);"}\n' +
      boundary + '--';

    res2 = http_send_recv3(
      method : "POST",
      item   : dir + "/login.aspx",
      data   : postdata,
      port   : port,
      add_headers  : make_array("Content-Type",
      "multipart/form-data; boundary=---------------------------xxxxxxxxxxxxx"),
      exit_on_fail : TRUE,
      follow_redirect : 2
    );

    if (
      ('id="controlbar_admin_advanced"' >< res2[2]) &&
      ('id="dnn_dnnLogin_enhancedLoginLink" title="Logout"' >< res2[2])
    )
    {
      login = TRUE;
    }

    # Versions 6.x
    if (!login)
    {
      viewstate_enc = urlencode(str:viewstate);
      validation_enc = urlencode(str:validation);

      postdata =
      "ScriptManager=dnn%24ctr%24dnn%24ctr%24Login_UPPanel%7Cdnn%24ctr%24Log" +
      "in%24Login_DNN%24cmdLogin&StylesheetManager_TSSM=&ScriptManager_TSM=" +
      "&__EVENTTARGET=dnn%24ctr%24Login%24Login_DNN%24cmdLogin&__EVENTARGUME" +
      "NT=&__VIEWSTATE=" +viewstate_enc+ "&__VIEWSTATEENCRYPTED=&__EVENTVALID" +
      "ATION=" +validation_enc+ "&dnn%24dnnSearch%24txtSearchNew=&dnn%24ctr" +
      "%24Login%24Login_DNN%24txtUsername=" +user+ "&dnn%24ctr%24Login%24Log" +
      "in_DNN%24txtPassword=" +pass+ "&ScrollTop=&__dnnVariable=%7B%22__scdof" +
      "f%22%3A%221%22%2C%22__dnn_pageload%22%3A%22__dnn_SetInitialFocus" +
      "(%5Cu0027dnn_ctr_Login_Login_DNN_txtUsername%5Cu0027)%3B%22%2C%22" +
      "SearchIconWebUrl%22%3A%22url(%2Ficons%2Fsigma%2FGoogleSearch" +
      "_16X16_Standard.png)%22%2C%22SearchIconSiteUrl%22%3A%22url(%2Ficons" +
      "%2Fsigma%2FDnnSearch_16X16_Standard.png)%22%2C%22SearchIconSelected" +
      "%22%3A%22S%22%7D&__ASYNCPOST=true&RadAJAXControlID=dnn_ctr_Login_UP";

      res2 = http_send_recv3(
        method : "POST",
        item   : dir + "/login.aspx",
        data   : postdata,
        port   : port,
        add_headers  : make_array("Content-Type",
          "application/x-www-form-urlencoded"),
        exit_on_fail : TRUE
      );

      if (
        (res2[0] =~ "^HTTP/[0-9.]+ 200 OK") &&
        (res2[2] =~ "^[0-9]+\|pageRedirect\|")
      )
      {
        login = TRUE;
      }
    }

    # Versions 5.x
    if (!login)
    {
      postdata = boundary + '\n' +
        'Content-Disposition: form-data; name="__EVENTTARGET"\n' +
        '\n' + 'dnn$ctr$Login$Login_DNN$cmdLogin\n' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="__EVENTARGUMENT"\n' +
        '\n\n' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="__VIEWSTATE"\n' +
        '\n' + viewstate + '\n' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="dnn$dnnSEARCH$txtSearchNew"\n' +
        '\n\n' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="dnn$ctr$Login$Login_DNN$txtUser'
        + 'name"\n' +
        '\n' + user + '\n' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="dnn$ctr$Login$Login_DNN$txtPass'
        +'word"\n' +
        '\n' + pass + '\n' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="ScrollTop"\n' +
        '\n\n' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="__dnnVariable"\n' +
        '\n' +
        '{"dshReset_imgIcon:exp":"-1","dshQuestionAnswer_imgIcon:exp":"-1","' +
        '__scdoff":"1","__dnn_pageload":"__dnn_SetInitialFocus' +
        "('dnn_ctr_Login_Login_DNN_txtUsername')" + ';","SearchIconWebUrl":"ur'+
        'l(/images/Search/google-icon.gif)","SearchIconSiteUrl":"url(/images' +
        '/Search/dotnetnuke-icon.gif)","SearchIconSelected":"S","dnn_dnnNAV_' +
        'ctldnnNAV_json":"","dnn_dnnNAV_ctldnnNAV_p":""}\n' +
        boundary + '--';

      res2 = http_send_recv3(
        method : "POST",
        item   : dir + "/login.aspx",
        data   : postdata,
        port   : port,
        add_headers  : make_array("Content-Type",
        "multipart/form-data; boundary=---------------------------xxxxxxxxxxxxx"),
        exit_on_fail    : TRUE,
        follow_redirect : 2
      );

      if (
        ('">Logout</a>' >< res2[2]) &&
        ("dnn$IconBar.ascx$cmdHost" >< res2[2])
      )
      {
          login = TRUE;
      }
    }

    # Versions 4.x
    if (!login)
    {
      postdata = boundary + '\n' +
        'Content-Disposition: form-data; name="__EVENTTARGET"\n' +
        '\n' + 'dnn$ctr$Login$Login_DNN$cmdLogin\n' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="__EVENTARGUMENT"\n' +
        '\n\n' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="__VIEWSTATE"\n' +
        '\n' + viewstate + '\n' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="dnn$dnnSEARCH$Search"\n' +
        '\n' + '\noptSite' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="dnn$dnnSEARCH$txtSearch"\n' +
        '\n\n' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="dnn$ctr$Login$Login_DNN$txtUser'+
        'name"\n' +
        '\n' + user + '\n' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="dnn$ctr$Login$Login_DNN$txtPass'+
        'word"\n' +
        '\n' + pass + '\n' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="dnn$ctr$Login$Login_DNN$cmdLogin"'+
        '\n' + 'Login\n' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="ScrollTop"\n' +
        '\n\n' +
        boundary + '\n' +
        'Content-Disposition: form-data; name="__dnnVariable"\n' +
        '\n' +
        '{"dshReset_imgIcon:exp":"-1","dshQuestionAnswer_imgIcon:exp":"-1","' +
        '__scdoff":"1","__dnn_pageload":"__dnn_SetInitialFocus' +
        "('dnn_ctr_Login_Login_DNN_txtUsername')" + ';","SearchIconWebUrl":"ur'+
        'l(/images/Search/google-icon.gif)","SearchIconSiteUrl":"url(/images' +
        '/Search/dotnetnuke-icon.gif)","SearchIconSelected":"S","dnn_dnnNAV_' +
        'ctldnnNAV_json":"","dnn_dnnNAV_ctldnnNAV_p":""}\n' +
        boundary + '--';

      res2 = http_send_recv3(
        method : "POST",
        item   : dir + "/login.aspx",
        data   : postdata,
        port   : port,
        add_headers  : make_array("Content-Type",
        "multipart/form-data; boundary=---------------------------xxxxxxxxxxxxx"),
        exit_on_fail    : TRUE,
        follow_redirect : 2
      );

      if (
        ('">Logout</a>' >< res2[2]) &&
        ("icon_hostsettings_" >< res2[2])
      )
      {
        login = TRUE;
      }
    }
  }

  # Versions 3.x
  if (login_page3)
  {
    # Get  __EVENTVALIDATION, and __VIEWSTATE
    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : dir + dnn3url,
      exit_on_fail : TRUE
    );

    viewstate = eregmatch(pattern:viewstate_pat, string:res[2]);
    if (!isnull(viewstate))
      viewstate = viewstate[1];

    validation = eregmatch(pattern:validation_pat, string:res[2]);
    if (!isnull(validation))
      validation = validation[1];

    # For 3.x both values are required for a login
    if ( (isnull(viewstate)) || (isnull(validation)) ) return NULL;

    postdata =
      boundary + '\n' +
      'Content-Disposition: form-data; name="__EVENTTARGET"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__EVENTARGUMENT"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="dnn$dnnSEARCH$txtSearch"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="dnn$ctr$Signin$txtUsername"\n' +
      '\n' + user + '\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="dnn$ctr$Signin$txtPassword"\n' +
      '\n' + pass + '\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="dnn$ctr$Signin$cmdLogin"\n' +
      '\n' + 'Login\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="ScrollTop"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__dnnVariable"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__EVENTVALIDATION"\n' +
      '\n' + validation + '\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__VIEWSTATE"\n' +
      '\n' + viewstate + '\n' +
      boundary + '--';

    res2 = http_send_recv3(
      method : "POST",
      port   : port,
      item   : dir + dnn3url,
      data   : postdata,
      add_headers : make_array("Content-Type",
      "multipart/form-data; boundary=---------------------------xxxxxxxxxxxxx"),
      exit_on_fail : TRUE,
      follow_redirect : 2
    );

    if (
      ('">Logout</a>' >< res2[2]) &&
      ("icon_hostsettings_" >< res2[2])
    )
    {
      login = TRUE;
    }
  }

  # Version 2.x
  if (login_page2)
  {
    # Get  __VIEWSTATE
    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : dir + dnn2url,
      exit_on_fail : TRUE
    );

    viewstate = eregmatch(
      pattern : 'name="__VIEWSTATE" value="(.+)"',
      string  : res[2]
    );
    if (!isnull(viewstate))
      viewstate = viewstate[1];

    if (isnull(viewstate)) return NULL;

    postdata =
      boundary + '\n' +
      'Content-Disposition: form-data; name="__EVENTTARGET"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__EVENTARGUMENT"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="_ctl0:_ctl6:_ctl0:txtUsername"\n' +
      '\n' + user + '\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="_ctl0:_ctl6:_ctl0:txtPassword"\n' +
      '\n' + pass + '\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="ScrollTop"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__VIEWSTATE"\n' +
      '\n' + viewstate + '\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="_ctl0:_ctl6:_ctl0:cmdLogin.x"\n' +
      '\n0\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="_ctl0:_ctl6:_ctl0:cmdLogin.y"\n' +
      '\n0\n' +
      boundary + '--';

    res2 = http_send_recv3(
      method : "POST",
      port   : port,
      item   : dir + dnn2url,
      data   : postdata,
      add_headers : make_array("Content-Type",
      "multipart/form-data; boundary=---------------------------xxxxxxxxxxxxx"),
      exit_on_fail : TRUE,
      follow_redirect : 2
    );
    if (
      ('">Logout</a>' >< res2[2]) &&
      ("icon_hostsettings_" >< res2[2])
    )
    {
      login = TRUE;
    }
  }

  # Version 1.x
  if (login_page1)
  {
    # Get  __EVENTVALIDATION, and __VIEWSTATE
    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : dir + dnn1url,
      exit_on_fail : TRUE
    );

    viewstate = eregmatch(pattern:viewstate_pat, string:res[2]);
    if (!isnull(viewstate))
      viewstate = viewstate[1];

    validation = eregmatch(pattern:validation_pat, string:res[2]);
    if (!isnull(validation))
      validation = validation[1];

    # For 1.x both values are required for a login
    if ( (isnull(viewstate)) || (isnull(validation)) ) return NULL;

    postdata =
      boundary + '\n' +
      'Content-Disposition: form-data; name="__EVENTTARGET"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__EVENTARGUMENT"\n' +
      '\n\n' +
      boundary + '\n' +
      'Content-Disposition: form-data; name="__VIEWSTATE"\n' +
      '\n' + viewstate + '\n' +
      boundary + '\n' +
     'Content-Disposition: form-data; name="ctl00$txtUsername"\n' +
     '\n' + user + '\n' +
     boundary + '\n' +
     'Content-Disposition: form-data; name="ctl00$txtPassword"\n' +
     '\n' + pass + '\n' +
     boundary + '\n' +
     'Content-Disposition: form-data; name="ScrollTop"\n' +
     '\n\n' +
     boundary + '\n' +
     'Content-Disposition: form-data; name="__EVENTVALIDATION"\n' +
     '\n' + validation + '\n' +
     boundary + '\n' +
     'Content-Disposition: form-data; name="ctl00$cmdLogin.x"\n' +
     '\n0\n' +
     boundary + '\n' +
     'Content-Disposition: form-data; name="ctl00$cmdLogin.y"\n' +
     '\n0\n' +
     boundary + '--';

    res2 = http_send_recv3(
      method : "POST",
      port   : port,
      item   : dir + dnn1url,
      data   : postdata,
      add_headers : make_array("Content-Type",
      "multipart/form-data; boundary=---------------------------xxxxxxxxxxxxx"),
      exit_on_fail : TRUE,
      follow_redirect : 2
    );

    if (
      ('">Logoff</a>' >< res2[2]) &&
      ("icon_hostsettings_" >< res2[2])
    )
    {
      login = TRUE;
    }
  }

  if (!login) return NULL;

  # Get link to Host Settings Dashboard. 5.x / 6.x / 7.x
  pats = make_list(
    '<li data-tabname="Dashboard"><a href="(.+)" >Dashboard',
    "<li data-tabname='Dashboard'><a href='(.+)'>Dashboard"
  );

  foreach pattern (pats)
  {
    dashboard = eregmatch(pattern:pattern, string:res2[2]);
    if (!isnull(dashboard))
    {
      dash_link = dashboard[1];
      dash_link = eregmatch(pattern:dir + '(.+)', string:dash_link);
      if (!isnull(dash_link))
      {
        dash_link = dash_link[1];
        break;
      }
    }
  }

  # 4.x
  if (isnull(dash_link))
  {
    link = eregmatch(
      pattern :'/Host/Host Settings/(.+)/Default\\.aspx(.*)iIdx=',
      string  : res2[2]
    );
    if (!isnull(link))
    {
      # Grab our Host Settings link
      pos = stridx(link[0], ">");
      if (pos > 0)
      {
        line = substr(link[0], 0, pos);
        link = eregmatch(
          pattern : '(/Host/Host Settings/(.+)/Default\\.aspx)',
          string  : line
        );
        if (!isnull(link)) dash_link=urlencode(str:link[0]);
      }
    }
  }

  # 3.x
  if (isnull(dash_link))
  {
    link = eregmatch(
      pattern :'/Host/Host Settings/(.+)/Default\\.aspx" image="icon_hostsetti',
      string  : res2[2]
    );
    if (!isnull(link))
    {
      # Grab our Host Settings link
      link = eregmatch(
        pattern : "/Host/Host Settings/(.+)/Default\.aspx",
        string  : link[0]
      );
      if (!isnull(link)) dash_link=urlencode(str:link[0]);
    }
  }

  # 1.x / 2.x
  if (isnull(dash_link))
  {
    link = eregmatch(
      pattern : 'title="&amp;nbsp;Host Settings" url="'+dir+'(.+)" image=',
      string  : res2[2]
    );
    if (!isnull(link))
    {
      pos = stridx(link[0], ">");
      if (pos > 0)
      {
        link = substr(link[0], 0, pos);
        link = eregmatch(
          pattern :  'title="&amp;nbsp;Host Settings" url="'+dir+'(.+)" image=',
          string : link
        );
        if (!isnull(link)) dash_link=link[1];
      }
    }
  }

  if (isnull(dash_link)) dash_link = "/Host/Dashboard.aspx";

  # Versions 9.x
  # Grab version from GetServerInfo API (9.x)
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + "/API/personaBar/ServerSummary/GetServerInfo",
    exit_on_fail    : TRUE,
    follow_redirect : 2
  );

  ver_str = strstr(res[2], '"ProductVersion"');
  if (!isnull(ver_str))
  {
    version = eregmatch(
      pattern:'"ProductVersion":"v. ([0-9\\.]+)',
      string  : ver_str
    );

    if(!isnull(version))
      version = version[1];
  }

  # Grab version from Host Settings
  res3 = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + dash_link,
    exit_on_fail    : TRUE,
    follow_redirect : 2
  );

  # Versions 8.x
  ver_str = strstr(res3[2], 'The product version.');
  if (!isnull(ver_str))
  {
    version = eregmatch(
      pattern:'\\</div\\>\\<span\\>([0-9\\.]+)\\</span\\>',
      string  : ver_str
    );

    if(!isnull(version))
      version = version[1];
  }

  # Versions 7.1.x
  ver_str = strstr(res3[2], 'The version of product.');
  if (!isnull(ver_str))
  {
    version = eregmatch(
      pattern:'\\</div\\>\\<span\\>([0-9\\.]+)\\</span\\>',
      string  : ver_str
    );

    if(!isnull(version))
      version = version[1];
  }

  # Versions 7.x / 6.x
  if (isnull(version))
  {
    ver_str = strstr(res3[2], 'DotNetNuke Version:</span>');
    if (!isnull(ver_str))
    {
      version = eregmatch(
        pattern : '\\</div\\>\\<span\\>([0-9\\.]+)\\</span\\>',
        string  : ver_str
      );

      if (!isnull(version))
        version = version[1];
    }
  }

  # Version 5.x
  if (isnull(version))
  {
    ver_str = strstr(res3[2], 'The version of DotNetNuke.');
    if (!isnull(ver_str))
    {
      version = eregmatch(
        pattern:'class="NormalTextBox">([0-9\\.]+)\\</span\\>',
        string : ver_str
      );
      if (!isnull(version))
        version = version[1];
    }
  }

  # Versions 3.x / 4.x
  if (isnull(version))
  {
    version = eregmatch(
      pattern:'HostSettings_lblVersion" class="NormalBold"\\>([0-9\\.]+)\\</span\\>',
      string : res3[2]
    );
    if (!isnull(version))
      version = version[1];
  }

  # Version 2.x
  if (isnull(version))
  {
    output = strstr(res3[2], '<select name="_ctl0:_ctl6:_ctl0:cboUpgrade"');
    matches = egrep(
      pattern : '\\<option value="([0-9\\.]+)"\\>',
      string : output
    );
    if (matches)
    {
      # We want the last match from the Upgrade Log as this will tell our
      # current version.  Same process is used in the 1.x check
      foreach match (split(matches, keep:FALSE))
      {
        version = eregmatch(pattern:'\\<option value="([0-9\\.]+)"\\>', string:match);
        if (!isnull(version))
          version = version[1];
      }
    }
  }

  # Version 1.x
  if (isnull(version))
  {
    output = strstr(res3[2], '<select name="ctl00$cboUpgrade"');
    matches = egrep(
      pattern : '\\<option value="([0-9\\.]+)"\\>',
      string : output
    );
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        version = eregmatch(pattern:'<option value="([0-9\\.]+)">', string:match);
        if (!isnull(version))
          version = version[1];
      }
    }
  }

  # 6.2 - 9.0.1: Check for DNN Security HotFix 1
  # http://www.dnnsoftware.com/community-blog/cid/155416/902-release-and-security-patch
  if (version =~ "^6\.2\.|^[7-9]\." && (ver_compare(ver:version, fix:'9.0.1', strict:FALSE) < 1))
  {
    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : dir + "/Host/DNN-Security-Hotfix-1",
      exit_on_fail : TRUE
    );

    if ("DNNSecurityHotFix1" >< res[2] && "You are patched." >< res[2])
    {
      set_kb_item(name:"DNN/SecurityHotFix1", value:1);
    }
  }

  if (!version) return NULL;
  # Normalize version output ie: version 03.00.04 becomes 3.0.4
  else
  {
    ver = split(version, sep:".", keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    {
      ver[i] = int(ver[i]);
      disp_ver += ver[i] + ".";
    }
    version = ereg_replace(string:disp_ver, pattern:"[\.]$", replace:"");
  }
  return version;
}

installs = 0 ;

foreach dir (dirs)
{
  found = FALSE;

  url = dir + '/Default.aspx';
  res = http_send_recv3(
    method : "GET",
    item   : url,
    port   : port,
    exit_on_fail : TRUE
  );

  # Check for a powered by message or link or any other page item that
  # suggets DNN is installed and further inspect the target to confirm
  if ('DotNetNuke' >< res[2])
  {
    # Versions 3.x.x / 4.x.x / 5.x.x / 6.x.x  / 7.x.x
    res2 = http_send_recv3(
      method : "GET",
      item   : dir + "/js/dnncore.js",
      port   : port,
      exit_on_fail : TRUE
    );
    if (
      "var DNN_" >< res2[2] &&
      "function __dnn_" >< res2[2]
    )
    {
      found = TRUE;
    }

    #  Versions 1.x.x / 2.x.x
    if (!found)
    {
      res2 = http_send_recv3(
        method : "GET",
        item   : dir + "/portal.css",
        port   : port,
        exit_on_fail : TRUE
      );
      if ("CSS STYLES FOR DotNetNuke" >< res2[2])
      {
        found = TRUE;
      }
    }

    if (found)
    {
      dnn_ver = dnn_login(port:port, dir:dir);
      if(isnull(dnn_ver)) dnn_ver = UNKNOWN_VER;

      register_install(
        app_name : app,
        path     : dir,
        port     : port,
        version  : dnn_ver,
        cpe      : "cpe:/a:dotnetnuke:dotnetnuke",
        webapp   : TRUE
      );
      installs++;

      if (!thorough_tests) break;
    }
  }
}
if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, app, port);

# Report findings.
report_installs(port:port);
