#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21778);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/05/21 20:40:31 $");

  script_cve_id("CVE-2006-0119");
  script_bugtraq_id(18020);
  script_osvdb_id(20506, 20507, 22426, 22427, 22428, 26924);

  script_name(english:"IBM Lotus Domino SMTP Server Malformed Meeting Request (vCal) DoS");
  script_summary(english:"Checks version of Lotus Domino SMTP server");

  script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is susceptible to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Lotus Domino, a messaging and collaboration
application suite. 

According to the version number in its banner, the SMTP server bundled
with Lotus Domino on the remote host reportedly suffers from a denial
of service flaw.  Specifically, the routing server will consumes 100%
of the CPU when attempting to process a malformed 'vcal' meeting
request.  An unauthenticated attacker may be able to leverage this
issue to deny service to legitimate users. 

In addition, IBM has identified several additional vulnerabilities that
affect this version.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/10761");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3532045c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Lotus Domino 6.5.4 FP1, 6.5.5 or 7.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/26");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");

  script_dependencie("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}


include("misc_func.inc");
include("smtp_func.inc");


port = get_service(svc:"smtp", default: 25, exit_on_fail: 1);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


# Check the banner.
banner = get_smtp_banner(port:port);
if (
  banner &&
  "Lotus Domino Release" >< banner &&
  egrep(pattern:"Release ([0-5]\.|6\.([0-4]|5\.([0-3]|4\))))", string:banner)
) security_hole(port);
