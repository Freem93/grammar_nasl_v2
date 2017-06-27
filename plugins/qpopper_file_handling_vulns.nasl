#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18361);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-1151", "CVE-2005-1152");
  script_bugtraq_id(13714);
  script_osvdb_id(16810, 16811);

  script_name(english:"Qpopper < 4.0.6 Multiple Insecure File Handling Local Privilege Escalation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote POP3 server is affected by multiple file handling flaws." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of the
Qpopper POP3 server that suffers from two local, insecure file
handling vulnerabilities.  First, it fails to properly drop root
privileges when processing certain local files, which could lead to
overwriting or creation of arbitrary files as root.  And second, it
fails to set the process umask, potentially allowing creation of
group- or world-writable files." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.gentoo.org/show_bug.cgi?id=90622" );
 script_set_attribute(attribute:"see_also", value:"http://www.mail-archive.com/qpopper@lists.pensive.org/msg05140.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Qpopper 4.0.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/23");
 script_cvs_date("$Date: 2011/03/16 13:37:59 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for insecure file handling vulnerabilities in Qpopper");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/pop3", 110);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("pop3_func.inc");


if (report_paranoia < 1) exit(0);	# FP on debian


port = get_service(svc:"pop3", default: 110, exit_on_fail: 1);
if (get_kb_item("pop3/"+port+"/false_pop3")) exit(0);


# There's a problem if the banner indicates version 4.0.5 or earlier.
banner = get_pop3_banner(port:port);
if (
  banner &&
  " QPOP " >< banner &&
  banner =~ " QPOP \(version ([0-3]\..*|4\.0\.[0-5])$"
) security_hole(port);
