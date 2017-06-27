#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(11401);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2002-0266");
  script_bugtraq_id(4035);
  script_osvdb_id(4313);
  script_xref(name:"EDB-ID", value:"21276");

  script_name(english:"Thunderstone Software TEXIS Nonexistent File Request Path Disclosure");
  script_summary(english:"Checks for TEXIS path disclosure.");

  script_set_attribute(attribute:"synopsis", value:
"A CGI application running on the remote host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Thunderstone Software TEXIS application running on the remote
host is affected by an information disclosure vulnerability that
allows an unauthenticated, remote attacker to obtain the full path of
the web root directory by making a specially crafted request for a
nonexistent file.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Feb/66");
  script_set_attribute(attribute:"solution", value:
"Upgrade Thunderstone Software TEXIS to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:thunderstone_software:texis");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

vuln = FALSE;
files = make_list("texis.exe", "texis.cgi", "texis");
file404 = "/" + rand_str() + "-" + SCRIPT_NAME - ".nasl";
file_regex = "Can't open source file (.*): No such file";

foreach dir (cgi_dirs())
{
  foreach file (files)
  {
    url = "/" + file + file404;
    res = http_send_recv3(
      method : "GET",
      item   : dir + url,
      port   : port,
      exit_on_fail : TRUE
    );
    if(
      ("Texis Web Script" >< res[2]) &&
      egrep(pattern:file_regex, string:res[2], icase:TRUE)
    )
    {
      vuln = TRUE;
      break;
    }
  }
}
if (vuln)
{
  output = strstr(res[2], "Texis Web Script");
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port     : port,
    severity : SECURITY_WARNING,
    generic  : TRUE,
    request  : make_list(build_url(qs:dir + url, port:port)),
    output   : chomp(output)
  );
  exit(0);
}
else
  audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
