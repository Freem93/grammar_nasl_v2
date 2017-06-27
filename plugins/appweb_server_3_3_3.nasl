#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61396);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/03/15 13:27:56 $");

  script_osvdb_id(89593);

  script_name(english:"Appweb 3.1.x / 3.2.x / 3.3.x < 3.3.3 mprUrlEncode Function Heap Overflow Vulnerability");
  script_summary(english:"Checks version in Server response header.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Appweb installed on the
remote host is 3.1.x, 3.2.x or 3.3.x earlier than 3.3.3.  It is,
therefore, potentially affected by a heap-based buffer overflow
vulnerability caused by a casting error in the function 'mprUrlEncode'
in the file 'src/mpr/mprLib.c'.

Note that Nessus did not actually test for this issue, but instead 
has relied on the version in the server's banner.

Further note that this issue reportedly only affects Appweb when
running on Microsoft Windows operating systems.");
  script_set_attribute(attribute:"see_also", value:"http://freecode.com/projects/appweb/releases/345430");
  # Issue tracker
  script_set_attribute(attribute:"see_also", value:"https://github.com/embedthis/appweb-4/issues/137");
  # Fix commit
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc55376e");
  script_set_attribute(attribute:"solution", value:"Upgrade to Appweb version 3.3.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mbedthis_software:mbedthis_appweb_http_server");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("appweb_server_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/appweb");
  script_require_ports("Services/www", 80, 7777);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (report_paranoia < 2)
{
  # Make sure this is Windows
  os = get_kb_item_or_exit("Host/OS");
  if ("Windows" >!< os) audit(AUDIT_OS_NOT, "Windows");
}

# Make sure this is Appweb.
get_kb_item_or_exit('www/'+port+'/appweb');

version = get_kb_item_or_exit('www/appweb/'+port+'/version', exit_code:1);
source  = get_kb_item_or_exit('www/appweb/'+port+'/source', exit_code:1);

# Affected 3.1.x, 3.2.x, 3.3.x < 3.3.3
fixed_ver = '3.3.3';
if (version =~ "^(3\.[12]($|[^0-9])|3\.3\.[0-2]($|[^0-9]))")
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_ver + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Appweb", port, version);
