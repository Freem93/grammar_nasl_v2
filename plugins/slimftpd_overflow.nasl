#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15704);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/11/17 15:15:44 $");

 script_cve_id("CVE-2004-2418", "CVE-2005-2373");
 script_bugtraq_id(11645, 14339);
 script_osvdb_id(11604, 18172);
 
 script_name(english:"SlimFTPd Multiple Command Handling Overflow");
 script_summary(english:"Checks version in the banner");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote FTP server is prone to multiple buffer overflow attacks."
 );
 script_set_attribute(
  attribute:"description", 
  value: 
"The remote host appears to be using SlimFTPd, a free, small,
standards-compliant FTP server for Windows. 

According to its banner, the version of SlimFTPd installed on the
remote host is prone to one or more buffer overflow attacks that can
lead to arbitrary code execution. 

Note that successful exploitation of either of these flaws requires an
attacker first authenticate."
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/fulldisclosure/2004/Nov/333"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2005/Jul/346"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade to SlimFTPd version 3.17 or later."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'SlimFTPd LIST Concatenation Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/10");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}


include("ftp_func.inc");


port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(1);


# There's a problem if...
if (
  # The version in the banner is <= 3.16 or...
  egrep(string:banner, pattern:"^220-SlimFTPd ([0-2]\.|3\.1[0-6][^0-9])")
) {
  security_hole(port);
}
