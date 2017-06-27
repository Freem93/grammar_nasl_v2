#
# This script was written by Paul Johnston of Westpoint Ltd <paul@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs, family change (8/10/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)

include("compat.inc");

if (description)
{
  script_id(11195);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2002-1357", "CVE-2002-1358", "CVE-2002-1359", "CVE-2002-1360");
  script_osvdb_id(8042, 8043, 8044, 8045);
  script_xref(name:"CERT-CC", value:"CA-2002-36");

  script_name(english:"SSH Multiple Remote Vulnerabilities");
  script_summary(english:"SSH Multiple Vulnerabilities 16/12/2002");

  script_set_attribute(attribute:"synopsis", value:"It may be possible to crash the SSH server on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote SSH server is affected by one or
more of the following vulnerabilities :

  - CVE-2002-1357 (incorrect length)

  - CVE-2002-1358 (lists with empty elements/empty strings)

  - CVE-2002-1359 (large packets and large fields)

  - CVE-2002-1360 (string fields with zeros)

The impact of successful exploitation of these vulnerabilities varies
across products.  In some cases, remote attackers will be able to
execute arbitrary code with the privileges of the SSH process (usually
root), although for the products currently tested, the maximum impact is
believed to be just a denial of service.");
  script_set_attribute(attribute:"see_also", value:"http://www.rapid7.com/advisories/R7-0009.txt");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2002/q4/88");
  script_set_attribute(attribute:"solution", value:"Contact the vendor for an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PuTTY Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/12/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO); 
  script_copyright(english:"This script is Copyright (C) 2002-2016 Paul Johnston, Westpoint Ltd");
  script_family(english:"Misc.");
  script_require_ports("Services/ssh", 22);
  script_dependencie("ssh_detect.nasl", "os_fingerprint.nasl");

  exit(0);
}

#
# The script code starts here
#
include("backport.inc");
port = get_kb_item("Services/ssh");
if (!port) port = 22;

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);


banner = get_backport_banner(banner:banner);


#
# SSH-2.0-3.2.0 F-Secure SSH Windows NT Server
# versions up to 3.1.* affected
#
if(ereg(pattern:"^SSH-2.0-([12]\..*|3\.[01]\..*) F-Secure SSH", string:banner, icase:TRUE))
{ 
  security_warning(port);
}

#
# SSH-2.0-3.2.0 SSH Secure Shell Windows NT Server
# versions up to 3.1.* affected
#
if(ereg(pattern:"^SSH-2.0-([12]\..*|3\.[01]\..*) SSH Secure Shell", string:banner, icase:TRUE))
{ 
  type = get_kb_item("Host/OS/Type");
  if ( isnull(type) || type == "embedded" ) exit(0);
  security_warning(port);
}

#
# SSH-1.99-Pragma SecureShell 3.0
# versions up to 2.* affected
#
if(ereg(pattern:"^SSH-1.99-Pragma SecureShell ([12]\..*)", string:banner, icase:TRUE))
{ 
  security_warning(port);
}
