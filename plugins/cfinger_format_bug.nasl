#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10652);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0243", "CVE-1999-0708", "CVE-2001-0609");
 script_bugtraq_id(2576, 651);
 script_osvdb_id(540, 541, 1078);

 script_name(english:"cfingerd < 1.4.4 Multiple Vulnerabilities");
 script_summary(english:"Checks the cfinger version");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote finger service has multiple vulnerabilities."
 );
 script_set_attribute( attribute:"description", value:
"The version of cfingerd running on the remote host has multiple
vulnerabilities, including :

  - A local buffer overflow in the GECOS field, which can be used to
    escalate privileges.
  - A format string vulnerability, triggered by a malformed ident
    reply.  This can be used to execute arbitrary code.
  - A local privilege escalation issue." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/1999/Sep/326"
 );
 # https://web.archive.org/web/20010725012119/http://archives.neohapsis.com/archives/vendor/2001-q2/0009.html
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?f2f0892c"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to cfingerd version 1.4.4 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/04/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "1996/09/19");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc."); 
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", 
 		     "cfinger_version.nasl");
 script_require_keys("cfingerd/version");
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;

version = get_kb_item("cfingerd/version");
if(version)
{
 if(ereg(pattern:"[0-1]\.(([0-3]\.[0-9]*)|(4\.[0-3]))",
 	string:version))security_hole(port);
}
