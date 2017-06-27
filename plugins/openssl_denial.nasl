#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(12110);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2017/02/22 19:25:29 $");

 script_cve_id("CVE-2004-0079", "CVE-2004-0081", "CVE-2004-0112");
 script_bugtraq_id(9899);
 script_osvdb_id(4316, 4317, 4318);

 script_name(english:"OpenSSL < 0.9.6m / 0.9.7d Multiple Remote DoS");
 script_summary(english:"Checks for version of OpenSSL");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is using a version of OpenSSL
which is older than 0.9.6m / 0.9.7d.  There are several bugs in such
versions that may allow an attacker to cause a denial of service
against the remote host." );
 script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20040317.txt" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Mar/155" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 0.9.6m / 0.9.7d or newer." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/17");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/03/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/17");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 if ( ! defined_func("bn_random") )
 	script_dependencie("http_version.nasl");
 else
 	script_dependencie("http_version.nasl", "macosx_SecUpd20040503.nasl", "redhat-RHSA-2004-119.nasl", "redhat-RHSA-2004-120.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here - we rely on Apache to spit OpenSSL's
# version. That sucks.
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");



if ( get_kb_item("CVE-2004-0079") ) exit(0);
if ( get_kb_item("CVE-2004-0081") ) exit(0);

#
# Only look at the banner for now. This test needs to be improved.
# 
ports = add_port_in_list(list:get_kb_list("Services/www"), port:443);

foreach port (ports)
{
 banner = get_http_banner(port:port);
 if(banner)
  {
  banner = get_backport_banner(banner:banner);
  if  ( ! banner || backported ) continue;
  if(egrep(pattern:"^Server:.*OpenSSL/0\.9\.([0-5][^0-9]|6[^a-z]|6[a-l]).*", string:banner)) security_warning(port);
  else if(egrep(pattern:"^Server:.*OpenSSL/0\.9\.7(-beta.*|[a-c]| .*)", string:banner)) security_warning(port);
  }
}
