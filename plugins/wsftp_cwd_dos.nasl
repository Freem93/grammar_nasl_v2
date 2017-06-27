#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14586);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2011/11/28 21:39:47 $");

  script_cve_id("CVE-1999-0362");
  script_bugtraq_id(217);
  script_osvdb_id(937);

  script_name(english:"WS_FTP Server CWD Command Remote DoS");
  script_summary(english:"Check WS_FTP server version");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FTP server has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of WS_FTP running on the remote
host has a denial of service vulnerability.  Sending a 'CWD' command
followed by a long argument causes the service to crash."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of WS_FTP."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/31");
  script_set_attribute(attribute:"vuln_publication_date", value: "1999/02/02");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes(); 
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
  script_family(english:"FTP");

  script_dependencie("ftp_anonymous.nasl","ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
 
  exit(0);
}

#

include ("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (! banner) exit(1);

if (egrep(pattern:"WS_FTP Server 1\.0\.[0-2][^0-9]", string: banner))
	security_warning(port);
