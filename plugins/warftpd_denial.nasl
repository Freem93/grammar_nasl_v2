#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(16270);
  script_cve_id("CVE-2005-0312");
  script_bugtraq_id(12384);
  script_osvdb_id(13225);
  script_version("$Revision: 1.12 $");

  script_name(english:"WarFTPd CWD Command Remote DoS");
  script_summary(english:"Checks the version of War FTP");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote FTP service is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is running War FTP Daemon, an FTP server for Windows.

The remote version of this software is prone to a remote denial of
service vulnerability.  An attacker may exploit this flaw to crash the
remote service."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to War FTP Daemon 1.82-RC10."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=110687202332039&w=2'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/27");
 script_cvs_date("$Date: 2016/11/29 20:13:37 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  exit(0);
}


include("ftp_func.inc");

port = get_ftp_port(default: 21);

r = get_ftp_banner(port:port);
if (!r) exit(1);

 if(egrep(pattern:"WarFTPd 1\.([0-9]\.|[0-7][0-9]\.|8[0-1]\.|82\.00-RC[0-9][^0-9]).*Ready",string:r))
 {
  security_warning(port);
 }

