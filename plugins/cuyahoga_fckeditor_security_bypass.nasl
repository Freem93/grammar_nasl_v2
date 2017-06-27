#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24003);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2007-0147");
  script_bugtraq_id(21927);
  script_osvdb_id(32643);

  script_name(english:"Cuyahoga FCKEditor Misconfiguration Unrestricted File Upload");
  script_summary(english:"Tries to call FCKEditor's upload.php script");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a .NET application that is affected by a
security bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cuyahoga, an open source .NET website
framework. 

The installation of Cuyahoga fails to require authorization to access
the FCKEditor component included with it.  An unauthenticated, remote
attacker may be able to leverage this flaw to view and upload files
with FCKEditor." );
 script_set_attribute(attribute:"see_also", value:"http://www.cuyahoga-project.org/10/section.aspx/61" );
 script_set_attribute(attribute:"solution", value:
"Either retrieve the updated 'Web.config' file and place it in the
'Support/FCKeditor/editor/filemanager' directory of the affected site
or upgrade to Cuyahoga 1.0.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/05");
 script_cvs_date("$Date: 2014/04/25 21:05:50 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:cuyahoga:cuyahoga");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_asp(port:port)) exit(0);


# Loop through directories.
foreach dir (make_list(cgi_dirs()))
{
  # Check if one of the script exists.
  url = string(dir, "/Support/FCKEditor/editor/filemanager/upload/asp/upload.asp");
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if it does and is not disabled.
  if ("OnUploadCompleted" >< res && "file uploader is disabled" >!< res)
  {
    security_warning(port);
    exit(0);
  }
}
