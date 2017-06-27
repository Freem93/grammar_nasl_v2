#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(36074);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2016/11/28 21:52:55 $");

 script_cve_id("CVE-2009-0839",
               "CVE-2009-0840",
               "CVE-2009-0841",
               "CVE-2009-0842",
               "CVE-2009-0843",
               "CVE-2009-1176",
               "CVE-2009-1177");
 script_bugtraq_id(34306);
 script_osvdb_id(56329, 56330, 56331, 56332, 56333, 56334, 56335);
 script_xref(name:"Secunia", value:"34520");

 script_name(english:"MapServer < 5.2.2 / 4.10.4 Multiple Flaws");
 script_summary(english:"Performs a banner check");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by
multiple flaws.");
 script_set_attribute(attribute:"description", value:
"The remote host is running MapServer, an open source Internet map
server. The installed version of MapServer is affected by multiple
flaws :

  - By creating a map file with overly long IMAGEPATH and/or
    NAME attribute(s), it may be possible to trigger a
    stack-based buffer overflow. (CVE-2009-0839)

  - It may be possible to trigger a heap-based buffer
    overflow by sending a HTTP POST request with
    'CONTENT_LENGTH' attribute set to '-1'. (CVE-2009-0840)
    Note: According to some reports this issue might have
    been incorrectly fixed, see references for more info.

  - It may be possible to create arbitrary files by
    specifying file names to the 'id' parameter.
    (CVE-2009-0841)

  - Provided an attacker has privileges to create symlinks
    on the file system, it may be possible to partially read
    the contents of arbitrary files. (CVE-2009-0842)

  - Provided an attacker has knowledge of a valid map file,
    it may be possible to determine if an arbitrary file
    exists on the remote system. (CVE-2009-0843)

  - Sufficient boundary checks are not performed on 'id'
    parameter in mapserver.c. An attacker may exploit
    this issue to trigger a buffer overflow condition
    resulting in arbitrary code execution on the remote
    system. (CVE-2009-1176)

  - File maptemplate.c is affected by multiple stack-based
    overflow issues. (CVE-2009-1177)");
 script_set_attribute(attribute:"see_also", value:"http://www.positronsecurity.com/advisories/2009-000.html");
 script_set_attribute(attribute:"see_also", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/1861");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2009/Mar/442");
 script_set_attribute(attribute:"see_also", value:"http://lists.osgeo.org/pipermail/mapserver-users/2009-March/060600.html");
 script_set_attribute(attribute:"solution", value:"Upgrade to MapServer 5.2.2/4.10.4.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 22, 119, 200);

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/02");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

 script_dependencies("mapserver_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/mapserver", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "MapServer";
port = get_http_port(default:80);
install = get_install_from_kb(appname:'mapserver', port:port, exit_on_fail:TRUE);
version = install['ver'];
url = build_url(port:port, qs:install['dir']);

# Determine fixed version from branch.
if (version =~ "^[0-4]($|[-\.])") fix = "4.10.4";
else if (version =~ "^5($|[-\.])") fix = "5.2.2";
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);

if (ver_compare(app:'asterisk', ver:version, fix:fix) == -1 )
{
  if(report_verbosity > 0)
  {
    report =
      '\n  URL           : ' + url +
      '\n  Version       : ' + version +
      '\n  Fixed version : ' + fix +
      '\n';
    security_hole(port:port,extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);
