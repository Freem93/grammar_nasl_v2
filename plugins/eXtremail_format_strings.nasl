#
# (C) Tenable Network Security, Inc.
#

# Ref: http://online.securityfocus.com/archive/1/192791
#
# Could not find a vulnerable copy -> we rely on banner version instead
#
# *untested*

include("compat.inc");


if(description)
{
 script_id(11100);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2001-1078");
 script_bugtraq_id(2908);
 script_osvdb_id(14148);
 
 script_name(english:"eXtremail Multiple SMTP Command flog Function Format String");
 script_summary(english:"Checks the version number");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has a format string vulnerability."
 );
 script_set_attribute(  attribute:"description",  value:
"According to its version number, the remote eXtremail server has
a format string vulnerability.  A remote attacker could exploit this
to crash the service, or possibly execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2001/Jun/312"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to eXtremail 1.1.10 or later."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/06/22");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");
port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);
if(banner)
{
 if(egrep(pattern:".*eXtremail V1\.1\.[5-9][^0-9]*", string:banner))
 	security_hole(port);
}

