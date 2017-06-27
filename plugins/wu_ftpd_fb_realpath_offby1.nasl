#
# (C) Tenable Network Security, Inc.
#

# Ref:
# 
# Date: Thu, 31 Jul 2003 18:16:03 +0200 (CEST)
# From: Janusz Niewiadomski <funkysh@isec.pl>
# To: vulnwatch@vulnwatch.org, <bugtraq@securityfocus.com>
# Subject: [VulnWatch] wu-ftpd fb_realpath() off-by-one bug



include("compat.inc");

if(description)
{
 script_id(11811);
 script_bugtraq_id(8315);
 script_cve_id("CVE-2003-0466");
 script_osvdb_id(2133);
 script_xref(name:"RHSA", value:"2003:245-01");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:032");
 script_version ("$Revision: 1.26 $");
 
 script_name(english:"WU-FTPD fb_realpath() Function Off-by-one Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote WU-FTPD server seems to be vulnerable to an off-by-one
overflow when dealing with huge directory structures. 

An attacker may exploit this flaw to obtain a shell on this host. 

Note that Nessus has solely relied on the banner of the remote server
to issue this warning so it may be a false-positive, especially if the
patch has already been applied." );
 script_set_attribute(attribute:"see_also", value:"http://www.securiteam.com/unixfocus/5ZP010AAUI.html" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Aug/43" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9eabbd45" );
 script_set_attribute(attribute:"solution", value:
"Apply the realpath.patch patch." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
		
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/07/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/07/31");
 script_cvs_date("$Date: 2016/11/01 19:59:57 $");
script_set_attribute(attribute:"potential_vulnerability", value:"true");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

		    
 script_summary(english:"Checks the banner of the remote wu-ftpd server");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
		  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/wuftpd", "Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);
  
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");
include("backport.inc");
include("global_settings.inc");
include("audit.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_ftp_port(default: 21);

banner = get_backport_banner(banner:get_ftp_banner(port: port));
if (! banner ) exit(1);
if(egrep(pattern:".*(wu|wuftpd)-(2\.(5\.|6\.[012])).*", string:banner))security_hole(port);
