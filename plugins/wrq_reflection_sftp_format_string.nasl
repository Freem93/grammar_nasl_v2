#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20902);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-0705");
  script_bugtraq_id(16625);
  script_osvdb_id(23172);
  script_xref(name:"CERT", value:"419241");

  script_name(english:"AttachmateWRQ Reflection for Secure IT Server SFTP Format String");
  script_summary(english:"Checks for format string vulnerability in AttachmateWRQ Reflection for Secure IT Server SFTP subsystem");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is affected by a format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running AttachmateWRQ Reflection for Secure IT
Server / F-Secure SSH Server, a commercial SSH server. 

According to its banner, the installed version of this software
contains a format string vulnerability in its sftp subsystem.  A
remote, authenticated attacker may be able to execute arbitrary code
on the affected host subject to his privileges or crash the server
itself." );
 script_set_attribute(attribute:"see_also", value:"http://support.wrq.com/techdocs/1882.html" );
 script_set_attribute(attribute:"solution", value:
"Either upgrade as described in the vendor advisory above or edit the
software's configuration to disable the SFTP subsystem." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/13");
 script_cvs_date("$Date: 2012/12/10 03:02:35 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


port = get_kb_item("Services/ssh");
if (!port) port = 22;


banner = get_kb_item("SSH/banner/" + port);
if (banner) {
  if ("ReflectionForSecureIT" >< banner) {
    if (
      # Reflection for Secure IT Windows Server versions 6.x < 6.0 build 38.
      egrep(pattern:"WRQReflectionForSecureIT_6\.0 Build ([0-2]|3[0-4])", string:banner) ||
      # Reflection for Secure IT UNIX Server versions 6.x < 6.0.0.9.
      egrep(pattern:"ReflectionForSecureIT_6\.0\.0\.[0-8]", string:banner)
    ) security_warning(port);
  }
  else if ("F-Secure SSH" >< banner) {
    if (
      #  F-Secure SSH Server for Windows versions 5.x < 5.3 build 35.
      egrep(pattern:"SSH-2\.0-5\.([0-2].*|3 Build ([0-2].*|3[0-4])) F-Secure SSH Windows", string:banner) ||
      #  F-Secure SSH Server for UNIX versions 3.x and 5.x < 5.0.8.
      egrep(pattern:"SSH-2\.0-(3\..*|5\.0\.[0-7]) F-Secure SSH", string:banner)
    ) security_warning(port);
  }
}
