#
# (C) Tenable Network Security, Inc.
#


# Ref:
#  Date: Wed, 9 Jun 2004 15:00:04 +0200
#  From: Stefan Esser <s.esser@e-matters.de>
#  To: full-disclosure@lists.netsys.com, bugtraq@securityfocus.com,
#        red@heisec.de, news@golem.de
#  Subject: Advisory 09/2004: More CVS remote vulnerabilities
#

include("compat.inc");

if (description)
{
 script_id(12265);
 script_version("$Revision: 1.24 $");

 script_cve_id("CVE-2004-0414", "CVE-2004-0416", "CVE-2004-0417", "CVE-2004-0418", "CVE-2004-1471"); 
 script_bugtraq_id(10499);
 script_osvdb_id(6830, 6831, 6832, 6833, 6834, 6835, 6836, 15727);
 script_xref(name:"RHSA", value:"2004:233-017");
 
 script_name(english:"CVS < 1.11.17 / 1.12.9 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote CVS server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote CVS server, according to its version number, might allow an
attacker to execute arbitrary commands on the remote system because of
a flaw relating to malformed Entry lines which lead to a missing NULL
terminator. 

Among the issues deemed likely to be exploitable were:

  - A double-free relating to the error_prog_name string. 
    (CVE-2004-0416)

  - An argument integer overflow. (CVE-2004-0417)

  - Out-of-bounds writes in serv_notify. (CVE-2004-0418)" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Jun/234" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CVS 1.12.9 or 1.11.17." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/06/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/06/09");
 script_cvs_date("$Date: 2017/05/11 13:46:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Logs into the remote CVS server and asks the version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service1.nasl", "cvs_pserver_heap_overflow.nasl");
 exit(0);
}

include('global_settings.inc');

port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if(!get_port_state(port))exit(0);
version =  get_kb_item(string("cvs/", port, "/version"));
if ( ! version ) exit(0);
if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.([0-9][^0-9]|1[0-6])|12\.[0-8][^0-9]).*", string:version))
     	security_hole(port);
