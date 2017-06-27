#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


# References:
# From: Stefan Esser <s.esser@e-matters.de>
# Subject: Advisory 01/2003: CVS remote vulnerability
# To: full-disclosure@lists.netsys.com, bugtraq@securityfocus.com,
#   vulnwatch@vulnwatch.org
# Message-ID: <20030120212523.GA17993@php.net>
# Date: Mon, 20 Jan 2003 22:25:23 +0100
   
if(description)
{
 script_id(11385);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2003-0015");
 script_bugtraq_id(6650);
 script_osvdb_id(3227);
 script_xref(name:"RHSA", value:"2003:012-07");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:0007");
 
 script_name(english:"CVS Malformed Directory Request Double-free Privilege Escalation");
 script_summary(english:"Logs into the remote CVS server and asks the version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote revision control service has a privilege escalation
vulnerability." );
 script_set_attribute( attribute:"description", value:
"According to its version number, the CVS server running on the remote
host has a double free bug, which could allow a malicious user to
elevate their privileges." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://marc.info/?l=bugtraq&m=104428571204468&w=2"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to CVS version 1.11.11 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/12/29");
 script_cvs_date("$Date: 2016/11/17 21:38:53 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service1.nasl", "cvs_pserver_heap_overflow.nasl");
 exit(0);
}

include('global_settings.inc');

port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if(!get_port_state(port))exit(0);

version = get_kb_item(string("cvs/", port, "/version"));
if ( ! version ) exit(0);
if(ereg(pattern:".* 1\.([0-9]\.|10\.|11\.[0-4][^0-9]).*", string:version))
     	security_hole(port);
