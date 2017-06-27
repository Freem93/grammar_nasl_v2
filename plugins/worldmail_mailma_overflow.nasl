#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24757);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-6336");
  script_bugtraq_id(21897);
  script_xref(name:"OSVDB", value:"32587");

  script_name(english:"Eudora WorldMail Mail Management Server (MAILMA.exe) Remote Overflow");
  script_summary(english:"Tries to access WorldMail MAILMA service");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Eudora WorldMail, a commercial mail server
for Windows.

According to its banner, the version of Eudora Worldmail installed on
the remote host contains a heap-based buffer overflow flaw in its Mail
Management Agent.  Using a specially crafted request, an
unauthenticated, remote attacker may be able to leverage this issue to
crash the affected service or execute arbitrary code on the remote
host.  Since the service runs with LOCAL SYSTEM privileges by default,
this could lead to a complete compromise of the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-001.html" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Jan/137" );
 script_set_attribute(attribute:"solution", value:
"Either block access to the affected port or switch to another product
as the vendor is rumoured to have said it will not release a fix." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/05");
 script_cvs_date("$Date: 2016/11/02 20:50:26 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/01/05");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/mailma", 106);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc: "mailma", default: 106, exit_on_fail: 1);

banner = get_service_banner_line(service:"mailma", port:port);
if (
  banner && 
  # nb: don't worry about the banner -- there's no fix.
  egrep(pattern:"^[0-9][0-9][0-9] .*WorldMail Mail Management Server", string:banner)
) security_hole(port);
