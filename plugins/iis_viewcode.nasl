#
# This script was written by John Lampe (j_lampe@bellsouth.net)
#
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if (description)
{
  script_id(10576);
  script_version("$Revision: 1.39 $");
  script_cvs_date("$Date: 2014/05/26 00:33:32 $");

  script_cve_id("CVE-1999-0737");
  script_bugtraq_id(167);
  script_osvdb_id(474);
  script_xref(name:"MSFT", value:"MS99-013");

  script_name(english:"Microsoft IIS / Site Server viewcode.asp Arbitrary File Access");
  script_summary(english:"Check for existence of viewcode.asp");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The file viewcode.asp is a default IIS file that can give a malicious
user a lot of unnecessary information about your file system or source
files. Specifically, viewcode.asp can allow a remote user to
potentially read any file on a web server hard drive.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms99-013");
  script_set_attribute(attribute:"solution", value:
"If you do not need these files, then delete them, otherwise use
suitable access control lists to ensure that the files are not
world-readable.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/12/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"(C) 2000-2014 John Lampe <j_lampe@bellsouth.net>");

  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_keys("Settings/ParanoidReport", "www/ASP");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


fl[0] = "/Sites/Knowledge/Membership/Inspired/ViewCode.asp";
fl[1] = "/Sites/Knowledge/Membership/Inspiredtutorial/Viewcode.asp";
fl[2] = "/Sites/Samples/Knowledge/Membership/Inspired/ViewCode.asp";
fl[3] = "/Sites/Samples/Knowledge/Membership/Inspiredtutorial/ViewCode.asp";
fl[4] = "/Sites/Samples/Knowledge/Push/ViewCode.asp";
fl[5] = "/Sites/Samples/Knowledge/Search/ViewCode.asp";
fl[6] = "/SiteServer/Publishing/viewcode.asp";


list = "";

for(i=0;fl[i];i=i+1)
{
 url = fl[i];
 if(is_cgi_installed_ka(item:url, port:port))
  {
   list = string(list, "\n", url);
  }
 }

if(strlen(list))
{
 mywarning = string("The following files were found on the remote\n",
 			"web server : ", list,
  	 		"\nThese files allow anyone to read arbitrary files on the remote host\n",
    		"Example, http://your.url.com/pathto/viewcode.asp?source=../../../../autoexec.bat\n",
    		"\n\nSolution : delete these files\n",
    		"Risk factor : High");
 security_warning(port:port, extra:mywarning);
 }


