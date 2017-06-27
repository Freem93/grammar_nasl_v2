#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15396);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2001-0784");
 script_bugtraq_id(2932);
 script_osvdb_id(1883);
 script_xref(name:"DSA", value:"089");
 
 script_name(english:"Icecast Encoded Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote streaming audio server is affected by an information
disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server runs a version of Icecast, an open source 
streaming audio server, which is version 1.3.10 or older.

These versions are affected by a directory traversal flaw because the
application fails to properly sanitize user-supplied input.

An attacker could send a specially crafted URL to view arbitrary files 
on the system.

*** Nessus reports this vulnerability using only
*** information that was gathered." );
 script_set_attribute(attribute:"see_also", value:"ftp://ftp.caldera.com/pub/security/OpenLinux/CSSA-2002-020.0.txt" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jun/373" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Icecast 1.3.12 or later as this reportedly fixes the issue." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:icecast:icecast");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/06/26");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Check icecast version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
		
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:8000);
if(!port) exit(0);

banner = tolower(get_http_banner(port:port));
if (! banner ) exit(0);

if("icecast/" >< banner && 
   egrep(pattern:"icecast/1\.([012]\.|3\.[0-9][^0-9])", string:banner))
      security_warning(port);
