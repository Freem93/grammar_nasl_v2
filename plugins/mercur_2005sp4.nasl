#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21728);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-7038", "CVE-2006-7039", "CVE-2006-7040", "CVE-2006-7041");
  script_bugtraq_id(18462);
  script_osvdb_id(26515, 26516, 26517, 26518, 26519, 26520, 26521);

  script_name(english:"MERCUR Messaging < 2005 SP4 Multiple Remote DoS Vulnerabilities");
  script_summary(english:"Checks version of MERCUR Messaging");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by multiple denial of service
flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running MERCUR Messaging, a commercial
mail server for Windows. 

According to its banner, the version of MERCUR Messaging installed on
the remote host is affected by various denial of service attacks
affecting the SMTP, POP3, and IMAP servers." );
 script_set_attribute(attribute:"see_also", value:"http://www.atrium-software.com/download/McrReadMe_EN.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MERCUR Messaging version 2005 SP4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/10");
 script_cvs_date("$Date: 2011/03/11 20:59:04 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "popserver_detect.nasl", "imap4_banner.nasl");
  if (NASL_LEVEL >= 3000 )
    script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/imap", 143, 32000);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");
include("misc_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");


# Do banner checks of various ports. 
#
# - SMTP.
port = get_kb_item("Services/smtp");
if (!port) port = 25;
banner = get_smtp_banner(port:port);
if (banner)
{
  # nb: banner for 2005 SP4 reads, in part, "MERCUR SMTP Server (v5.00.19".
  if (egrep(pattern:"^[0-9][0-9][0-9] .* MERCUR SMTP Server \(v([0-4]\.|5\.00\.(0[0-9]|1[0-8]))", string:banner))
  {
    security_hole(port);
    exit(0);
  }
  # Unless we're being paranoid, stop after getting the banner.
  if (report_paranoia < 2) exit(0);
}
# - POP3.
port = get_kb_item("Services/pop3");
if (!port) port = 110;
banner = get_pop3_banner(port:port);
if (banner)
{
  # nb: banner for 2005 SP4 reads, in part, "MERCUR POP3-Server (v5.00.12".
  if (egrep(pattern:"^(\+OK|-ERR) MERCUR POP3-Server \(v([0-4]\.|5\.00\.(0[0-9]|1[01]))", string:banner))
  {
    security_hole(port);
    exit(0);
  }
  # Unless we're being paranoid, stop after getting the banner.
  if (report_paranoia < 2) exit(0);
}
# - IMAP.
port = get_kb_item("Services/imap");
if (!port) port = 143;
banner = get_imap_banner(port:port);
if (banner)
{
  # nb: banner for 2005 SP4 reads, in part, "MERCUR IMAP4-Server (v5.00.14".
  if (egrep(pattern:"^\* (OK|BAD|NO) MERCUR IMAP4-Server \(v([0-4]\.|5\.00\.(0[0-9]|1[0-3]))", string:banner))
  {
    security_hole(port);
    exit(0);
  }
  # Unless we're being paranoid, stop after getting the banner.
  if (report_paranoia < 2) exit(0);
}
# - MERCUR Control Service
port = 32000;
banner = get_unknown_banner(port:port);
if (banner)
{
  # nb: banner for 2005 SP4 reads, in part, "MERCUR Control-Service (v5.00.14".
  if (egrep(pattern:"^MERCUR Control-Service \(v([0-4]\.|5\.00\.(0[0-9]|1[0-3]))", string:banner))
  {
    security_hole(port);
    exit(0);
  }
  # Unless we're being paranoid, stop after getting the banner.
  if (report_paranoia < 2) exit(0);
}
