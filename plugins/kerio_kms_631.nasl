#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23868);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-6554");
  script_bugtraq_id(21091);
  script_osvdb_id(32261);

  script_name(english:"Kerio MailServer < 6.3.1 Long LDAP Query DoS");
  script_summary(english:"Checks version of KMS SMTP server");

 script_set_attribute(attribute:"synopsis", value:
"The remote LDAP server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Kerio MailServer, a commercial mail server
available for Windows, Linux, and Mac OS X platforms. 

According to its banner, the LDAP service associated with the
installed version of Kerio MailServer terminates abnormally when it
receives certain malformed LDAP search requests.  An unauthenticated,
remote attacker can exploit this issue to deny access to legitimate
users." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/454455/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://forums.kerio.com/index.php?t=msg&th=10321&start=0" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Kerio MailServer 6.3.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/12/13");
 script_cvs_date("$Date: 2012/08/16 22:13:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:kerio:personal_mailserver");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");
  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");
  script_dependencies("ldap_detect.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/ldap", 389, "Services/smtp", 25);

  exit(0);
}


include("smtp_func.inc");


ldap_port = get_kb_item("Services/ldap");
if (!ldap_port) ldap_port = 389;
if (!get_port_state(ldap_port)) exit(0);


smtp_port = get_kb_item("Services/smtp");
if (!smtp_port) smtp_port = 25;
if (!get_port_state(smtp_port)) exit(0);


# Check the version in the SMTP banner.
banner = get_smtp_banner(port:smtp_port);
if (banner && banner =~ "^220 .* Kerio MailServer ([0-5]\.|6\.([0-2]\.|3\.0([^0-9]|$)))")
  security_warning(ldap_port);
