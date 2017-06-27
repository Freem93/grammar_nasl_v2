#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14598);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-2004-1848", "CVE-2004-1883", "CVE-2004-1884", "CVE-2004-1885");
 script_bugtraq_id(9953);
 script_osvdb_id(4539, 4540, 4541, 4542, 59291);

 script_name(english:"WS_FTP Server Multiple Vulnerabilities (OF, DoS, Cmd Exec)");
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FTP server has multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of WS_FTP running on the remote
host has multiple vulnerabilities, including :

  - A buffer overflow caused by a vulnerability in the ALLO handler.

  - A flaw which could allow an attacker to gain SYSTEM level
    privileges.

  - A local or remote attacker with write privileges on a directory
    can create a specially crafted file, causing a denial of service.

A remote attacker could exploit these vulnerabilities to execute
arbitrary code."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of WS_FTP."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/03/24");
 script_cvs_date("$Date: 2016/05/27 14:45:44 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

 summary["english"] = "Check WS_FTP server version";
  script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#

include ("ftp_func.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port:port);
if ( ! banner ) exit(1);

if (egrep(pattern:"WS_FTP Server ([0-3]\.|4\.0[^0-9.]|4\.0\.[12][^0-9])", string: banner))
	security_hole(port);
