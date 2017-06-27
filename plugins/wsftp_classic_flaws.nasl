#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14599);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/09/26 16:00:41 $");

  script_cve_id("CVE-1999-0017");
  script_bugtraq_id(6050, 6051);
  script_osvdb_id(51744, 87439);

  script_name(english:"WS_FTP Server Multiple Vulnerabilities (Bounce, PASV Hijacking)");
  script_summary(english:"Check WS_FTP server version");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FTP server has multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the remote WS_FTP server is
vulnerable to session hijacking during passive connections and to an
FTP bounce attack when a user submits a specially crafted FTP
command."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/1995/Jul/46"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of this software."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/01");
  script_set_attribute(attribute:"vuln_publication_date", value: "1995/07/12");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"FTP");

  script_dependencie("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
 
  exit(0);
}

#now the code

include ("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(1);

if (egrep(pattern:"WS_FTP Server ([0-2]\.|3\.(0\.|1\.[0-3][^0-9]))", string: banner))
	security_hole(port);
