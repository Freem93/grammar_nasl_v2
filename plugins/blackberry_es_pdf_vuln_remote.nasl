#
# (C) Tenable Network Security, Inc.
#

# @DEPRECATED@

# nb: Interim Security Software Update 2 for BlackBerry ES addresses this
#     issue too, and it patches only 3 DLLs w/o changing the version
#     observed remotely. Thus, a remote check is no longer reliable.
exit(0);


include("compat.inc");

if (description)
{
  script_id(33590);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/01/25 01:19:07 $");

  script_cve_id("CVE-2008-3246");
  script_bugtraq_id(30188);
  script_osvdb_id(47296);
  script_xref(name:"Secunia", value:"31092");
  script_xref(name:"Secunia", value:"31141");

  script_name(english:"BlackBerry Attachment Service PDF Processing Arbitrary Code Execution (uncredentialed check)");
  script_summary(english:"Checks build version in MDS-CS"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a code
execution vulnerability" );
 script_set_attribute(attribute:"description", value:
"The version of BlackBerry Enterprise Server / BlackBerry Unite! on the
remote host reportedly contains a vulnerability in the PDF distiller
component of the BlackBerry Attachment Service.  A remote attacker may
be able to leverage this issue to execute arbitrary code on the
affected host subject to the privileges under which the application
runs, generally 'Administrator', by sending an email message with a
specially crafted PDF file and having that opened for viewing on a
BlackBerry smartphone. 

Note that this plugin does not check if the Attachment Service has
been configured to not process PDF files so this may be a
false-positive." );
 script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/viewContent.do?externalId=KB15766" );
 script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/viewContent.do?externalId=KB15770" );
 script_set_attribute(attribute:"solution", value:
"If using BlackBerry Enterprise Server, either upgrade to version 4.1
Service Pack 6 (4.1.6), apply an appropriate interim security software
update, or prevent the Attachment Service from processing PDF files. 

If using BlackBerry Unite!, either upgrade to 1.0 Service Pack 1
(1.0.1) bundle 36 or later or prevent the Attachment Service from
processing PDF files." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# If the page looks like MDC-CS...
res = http_get_cache(item:"/", port:port);
if (res == NULL) exit(0);

if (
  "Page generated by MDS-CS" >< res &&
  "Research In Motion Limited" >< res &&
  ">Build version" >< res
)
{
  # Extract the version number.
  version = strstr(res, ">Build version") - ">Build version";
  if ("<td>" >< version)
  {
    version = strstr(version, "<td>") - "<td>";
    if ("</td" >< version) version = version - strstr(version, "</td");
  }
  if (version =~ "^[0-9]+[0-9.]+[0-9]$")
  {
    if (version =~ "^4\.1\.[3-5]($|[^0-9])")
    {
      security_hole(port);
    }
  }
}
