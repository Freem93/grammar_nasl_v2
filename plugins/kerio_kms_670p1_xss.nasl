#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39354);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2009-2636");
  script_bugtraq_id(35264);
  script_osvdb_id(54928);
  script_xref(name:"Secunia", value:"35392");

  script_name(english:"Kerio MailServer < 6.6.2 Patch 3 / 6.7.0 Patch 1 XSS (KSEC-2009-06-08-01)");
  script_summary(english:"Checks version in banners");

  script_set_attribute(attribute:"synopsis", value:
"The remote webmail server is affected by a cross-site scripting
issue.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
Kerio MailServer prior to 6.6.2 Patch 3 or 6.7.0 Patch 1.  The webmail
component of such versions is reportedly affected by a cross-site
scripting vulnerability on the Integration page. 

Successful exploitation of this issue could lead to execution of
arbitrary HTML and script code in a user's browser within the security
context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/support/security-advisories#0906");
  script_set_attribute(attribute:"solution", value:"Upgrade to Kerio MailServer 6.6.2 Patch 3 / 6.7.0 Patch 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);
  script_set_attribute(attribute:"cpe",value:"cpe:/a:kerio:kerio_mailserver");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("kerio_kms_641.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("kerio/port");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_kb_item('kerio/port');
if (isnull(port)) exit(1, "The 'kerio/port' KB item is missing.");

service = get_kb_item('kerio/'+port+'/service');
ver = get_kb_item('kerio/'+port+'/version');
display_ver = get_kb_item('kerio/'+port+'/display_version');
patch = get_kb_item('kerio/'+port+'/patch');

# Unless we are paranoid,
# exit if webmail is not running.

if(report_paranoia < 2)
{
 p = get_http_port(default:80);

 res = http_send_recv3(method:"GET", item:"/webmail/login.php", port:p, exit_on_fail:TRUE);
 if(!ereg(pattern:">Kerio MailServer .+ WebMail</", string:res[2])) exit(0);
}

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

# There's a problem if the version is < 6.6.2 patch 3 or 6.7.0 patch 1
if (
  (iver[0] == 6 && iver[1] == 6 && (iver[2] < 2 || (iver[2] == 2 && patch < 3))) ||
  (iver[0] == 6 && iver[1] == 7 && (iver[2] == 0 && patch < 1))
)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "According to its ", service, " banner, the remote host is running Kerio\n",
      "MailServer version ", display_ver, ".\n"
    );
    security_warning(port:port, extra:report);
   }
  else security_warning(port);
}
else exit(0, 'Kerio MailServer '+display_ver+' is not affected.');
