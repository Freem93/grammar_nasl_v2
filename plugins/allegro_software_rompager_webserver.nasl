#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(80228);
 script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2017/02/03 20:48:27 $");
 
 script_cve_id("CVE-2014-9222", "CVE-2014-9223");
 script_bugtraq_id(71744, 71756);
 script_osvdb_id(116043, 116044, 130547);
 script_xref(name:"CERT", value:"561444");

 script_name(english:"Allegro RomPager HTTP Cookie Management Remote Code Execution Vulnerability (Misfortune Cookie)");
 script_summary(english:"Checks the version of Allegro RomPager.");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple remote code execution
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
Allegro Software RomPager 4.07 to 4.33. It is, therefore, affected by
multiple vulnerabilities :

  - A flaw in HTTP cookie management in the embedded web
    server allows a remote attacker to execute arbitrary
    code with administrative privileges and to possibly
    conduct attacks against connected devices.
    (CVE-2014-9222)

  - A digest authentication buffer overflow flaw exists that
    allows a remote attacker to cause a denial of service or
    to execute arbitrary code. (CVE-2014-9223)");
 # http://mis.fortunecook.ie/too-many-cooks-exploiting-tr069_tal-oppenheim_31c3.pdf
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb698969");
 # http://www.checkpoint.com/blog/fortune-cookie-hole-internet-gateway/index.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c382846" );
 # http://mis.fortunecook.ie/misfortune-cookie-suspected-vulnerable.pdf
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?946b7793" );
 # https://www.allegrosoft.com/allegro-software-urges-manufacturers-to-maintain-firmware-for-highest-level-of-embedded-device-security/news-press.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22cba06d" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for an updated firmware image. Allegro addressed
both issues in mid-2005 with RomPager version 4.34.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:UC");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_set_attribute(attribute:"vuln_publication_date", value: "2014/12/18");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/07/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/24");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:allegrosoft:rompager");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80, 7547);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "Allegro RomPager";

fix = '4.34';
min = '4.07';

port = get_http_port(default:7547, embedded:TRUE);

banner = get_http_banner(port:port);

if(!banner)
  audit(AUDIT_WEB_NO_SERVER_HEADER, port);

if("RomPager" >!< banner)
  audit(AUDIT_NOT_DETECT , app_name, port);

pat = "Server:.*RomPager/([0-9]+\.[0-9]+)($|[^0-9])";
match = eregmatch(string:banner, pattern:pat);
if (isnull(match) || isnull(match[0]) || isnull(match[1])) audit(AUDIT_NOT_DETECT , app_name, port);

source  = match[0];
version = match[1];

if (
ver_compare(ver:version, fix:min, strict:FALSE) >= 0 &&
ver_compare(ver:version, fix:fix, strict:FALSE) < 0
)
{
    report = NULL;
    if (report_verbosity > 0)
    {
        report = '\n' +
          '\n  Source            : ' + source +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : ' + fix +
          '\n';

        security_hole(port:port, extra:report);
    }

    else security_hole(port:port);
} 
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
