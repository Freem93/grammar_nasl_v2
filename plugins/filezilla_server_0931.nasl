#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(45112);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2009-0884");
  script_bugtraq_id(34006);
  script_osvdb_id(52698);
  script_xref(name:"Secunia", value:"34089");

  script_name(english:"FileZilla Server < 0.9.31 Denial of Service");
  script_summary(english:"Checks the banner version of FileZilla Server"); 
  
  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of FileZilla Server installed on
the remote host is older than version 0.9.31.  An unspecified
vulnerability in the SSL code for such versions can be exploited by a
remote attacker to trigger a denial of service condition." );
  script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=665428" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to FileZilla Server version 0.9.31 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
  script_set_attribute(attribute:"vuln_publication_date", value: "2009/03/03");
  script_set_attribute(attribute:"patch_publication_date", value: "2009/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value: "2010/03/19");
 script_cvs_date("$Date: 2016/05/05 16:01:14 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
   script_set_attribute(attribute:"cpe", value:"cpe:/a:filezilla:filezilla_server");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_require_keys("ftp/filezilla");
  exit(0);
}

include("ftp_func.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (!banner) exit(1, "No FTP banner found on port "+port+".");
if ("FileZilla Server" >!< banner) exit(0, "Banner on port "+port+" doesn't look like FileZilla Server.");

banner = strstr(banner, "FileZilla Server");
banner = banner - strstr(banner, '\r\n');
if (ereg(pattern:"FileZilla Server version 0.([0-8]\.|9\.([0-9][a-e]*$|[0-2][0-9][a-e]*|30($|[^0-9])))",string:banner))
{
  if(report_verbosity > 0)
  {
    report = '\n' +
      'The remote FileZilla server returned the following banner :\n' +
      '\n' +
      "  " + banner + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port); 
}
