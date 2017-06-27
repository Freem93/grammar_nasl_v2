#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(11828);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2003-0743");
 script_bugtraq_id(8518);
 script_osvdb_id(10877);

 script_name(english:"Exim < 4.22 smtp_in.c HELO/EHLO Remote Overflow");
 script_summary(english:"Checks the version of the remote Exim daemon");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote SMTP server has a heap-based buffer overflow
vulnerability."
 );
 script_set_attribute( attribute:"description", value:
"According to its banner, the version of Exim running on the remote
host has a remote heap-based buffer overflow vulnerability.  A remote,
unauthenticated attacker could potentially exploit this to execute
arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://lists.exim.org/lurker/message/20030814.083154.40b19dfb.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://lists.exim.org/lurker/message/20030815.092719.8a26db10.html"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to Exim 4.21 or later, or apply the appropriate patches."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/09/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/08/14");
 script_cvs_date("$Date: 2014/05/12 23:01:52 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:exim:exim");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");

 script_dependencie("smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;

banner = get_smtp_banner(port:port);
if(!banner)exit(0);
if(egrep(pattern:"220.*Exim ([0-3]\.|4\.([0-9][^0-9]|1[0-9][^0-9]|2[01][^0-9]))", string:banner))security_hole(port);
